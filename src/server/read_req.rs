use async_io::Async;
use bytes::{BufMut, Bytes, BytesMut};
use futures_lite::{AsyncRead, AsyncReadExt};
use log::trace;
use std::cmp::min;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::slice;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::packet::{Opts, Packet, RwReq, PACKET_DATA_HEADER_LEN};
use crate::server::{ServerConfig, DEFAULT_BLOCK_SIZE};
use crate::utils::io_timeout;

pub(crate) struct ReadRequest<'r, R>
where
    R: AsyncRead + Send,
{
    peer: SocketAddr,
    socket: Async<UdpSocket>,
    reader: &'r mut R,
    buffer: BytesMut,
    block_size: usize,
    timeout: Duration,
    max_send_retries: u32,
    oack_opts: Option<Opts>,
    window_size: usize,
}

impl<'r, R> ReadRequest<'r, R>
where
    R: AsyncRead + Send + Unpin,
{
    pub(crate) async fn init(
        reader: &'r mut R,
        file_size: Option<u64>,
        peer: SocketAddr,
        req: &RwReq,
        config: ServerConfig,
        local_ip: IpAddr,
    ) -> Result<ReadRequest<'r, R>> {
        let oack_opts = build_oack_opts(&config, req, file_size);

        let block_size = oack_opts
            .as_ref()
            .and_then(|o| o.block_size)
            .map(usize::from)
            .unwrap_or(DEFAULT_BLOCK_SIZE);

        let negotiated_window_size: usize = oack_opts
            .as_ref()
            .and_then(|o| o.window_size)
            .unwrap_or(1u16) as usize;

        let timeout = oack_opts
            .as_ref()
            .and_then(|o| o.timeout)
            .map(|t| Duration::from_secs(u64::from(t)))
            .unwrap_or(config.timeout);

        let addr = SocketAddr::new(local_ip, 0);
        let socket = Async::<UdpSocket>::bind(addr).map_err(Error::Bind)?;

        Ok(ReadRequest {
            peer,
            socket,
            reader,
            buffer: BytesMut::with_capacity(
                PACKET_DATA_HEADER_LEN + block_size
            ),
            block_size,
            timeout,
            max_send_retries: config.max_send_retries,
            oack_opts,
            window_size: negotiated_window_size,
        })
    }

    pub(crate) async fn handle(&mut self) {
        if let Err(e) = self.try_handle().await {
            trace!("RRQ request failed (peer: {}, error: {})", &self.peer, &e);

            Packet::Error(e.into()).encode(&mut self.buffer);
            let buf = self.buffer.split().freeze();
            // Errors are never retransmitted.
            // We do not care if `send_to` resulted to an IO error.
            let _ = self.socket.send_to(&buf[..], self.peer).await;
        }
    }

    async fn try_handle(&mut self) -> Result<()> {
        let mut window: Vec<Bytes> =
            Vec::with_capacity(self.window_size);
        let mut block_id: u16;
        let mut window_base: u16 = 0;
        let mut buf:Bytes;
        let mut is_last_block:bool;

        (buf, is_last_block) = self.fill_data_block(1).await?;

        // Send OACK after we manage to read the first block from reader.
        //
        // We do this because we want to give the developers the option to
        // produce an error after they construct a reader.
        if let Some(opts) = self.oack_opts.as_ref() {
            trace!("RRQ OACK (peer: {}, opts: {:?}", &self.peer, &opts);
            let mut buff = BytesMut::new();
            Packet::OAck(opts.to_owned()).encode(&mut buff);

            window_base+=self.send_window(&[buff.split().freeze()], window_base).await?;
        }
        // push first data packet to the window
        window.push(buf);

        loop {
            // calculate next block_id, window might not be empty
            block_id = window_base.wrapping_add(window.len() as u16);

            while !is_last_block && (window.len() < self.window_size) {
                // we still have data and window is not full
                (buf, is_last_block) = self.fill_data_block(block_id).await?;
                window.push(buf);
                block_id = block_id.wrapping_add(1);
            }
            
            let blocks_acked = self.send_window(&window, window_base).await?;
            window_base = window_base.wrapping_add(blocks_acked);

            // remove acked blocks from window
            if blocks_acked == window.len() as u16{
                window.clear()
            }else {
                for _ in 0..blocks_acked {
                    window.remove(0);
                }
            }

            if is_last_block && window.is_empty(){
                // transfer is dome
                break;
            }
        }

        trace!("RRQ request served (peer: {})", &self.peer);
        Ok(())
    }

    async fn fill_data_block(&mut self, block_id: u16) -> Result<(Bytes, bool), Error> {
        Packet::encode_data_head(block_id, &mut self.buffer);

        // Read block in self.buffer
        let (buf,len) = unsafe {
            let uninit_buf = self.buffer.chunk_mut();

            let data_buf = slice::from_raw_parts_mut(
                uninit_buf.as_mut_ptr(),
                uninit_buf.len(),
            );

            let len = self.read_block(data_buf).await?;

            self.buffer.advance_mut(len);
            (self.buffer.split().freeze(), len)
        };

        if len == self.block_size {
            self.buffer.reserve(PACKET_DATA_HEADER_LEN + self.block_size);
            Ok((buf, false))
        }else {
            // last data block, we won't read anymore
            Ok((buf, true))
        }

    }

    async fn send_window(&mut self, window: &[Bytes], window_base: u16) -> Result<u16> {
        // Send packet until we receive an ack
        for _ in 0..=self.max_send_retries {
            for packet in window {
                self.socket.send_to(&packet[..], self.peer).await?;
            }
            
            match self.recv_ack(window_base, window.len() as u16).await {
                Ok(blocks_acked) => {
                    trace!(
                        "RRQ (peer: {}, window_base: {}, blocks_acked: {}, window_len: {}) - Received ACK",
                        &self.peer,
                        window_base,
                        blocks_acked,
                        window.len()
                    );
                    return Ok(blocks_acked);
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    trace!(
                        "RRQ (peer: {}, block_id: {}) - Timeout",
                        &self.peer,
                        window_base
                    );
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(Error::MaxSendRetriesReached(self.peer, window_base))
    }


    async fn recv_ack(&mut self, window_base: u16, window_len:u16) -> io::Result<u16> {
        // We can not use `self` within `async_std::io::timeout` because not all
        // struct members implement `Sync`. So we borrow only what we need.
        let socket = &mut self.socket;
        let peer = self.peer;

        io_timeout(self.timeout, async {
            let mut buf = [0u8; 1024];

            loop {
                let (len, recved_peer) = socket.recv_from(&mut buf[..]).await?;

                // if the packet do not come from the client we are serving, then ignore it
                if recved_peer != peer {
                    continue;
                }

                // parse only valid Ack packets, the rest are ignored
                if let Ok(Packet::Ack(recved_block_id)) =
                    Packet::decode(&buf[..len])
                {
                    let window_end = window_base.wrapping_add(window_len);

                    if window_end > window_base {
                        // the window did not wrap
                        if (recved_block_id >= window_base) && recved_block_id < window_end {
                            // number of blocks acked
                            return Ok(recved_block_id-window_base+1u16);
                        }
                        else {
                            trace!("Ack packet {recved_block_id} is out of window_base: {window_base}, window_len: {window_len}");
                        }
                    }else {
                        // the window is wrapped
                        if recved_block_id >= window_base {
                            trace!("Wrapped window right rcv:{recved_block_id} base:{window_base} len:{window_len} end: {window_end}");
                            return Ok(1u16+(recved_block_id-window_base));
                        } else if recved_block_id < window_end {
                            trace!("Wrapped window left rcv:{recved_block_id} base:{window_base} len:{window_len} end: {window_end}");
                            return Ok(1u16+recved_block_id+window_len-window_end);
                        } else {
                            trace!("Ack packet {recved_block_id} is out of window_base: {window_base}, window_len: {window_len}");
                        }
                    }
                }
            }
        })
        .await
    }

    async fn read_block(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut len = 0;

        while len < buf.len() {
            match self.reader.read(&mut buf[len..]).await? {
                0 => break,
                x => len += x,
            }
        }

        Ok(len)
    }
}

fn build_oack_opts(
    config: &ServerConfig,
    req: &RwReq,
    file_size: Option<u64>,
) -> Option<Opts> {
    let mut opts = Opts::default();

    if !config.ignore_client_block_size {
        opts.block_size = match (req.opts.block_size, config.block_size_limit) {
            (Some(bsize), Some(limit)) => Some(min(bsize, limit)),
            (Some(bsize), None) => Some(bsize),
            _ => None,
        };
    }

    if !config.ignore_client_timeout {
        opts.timeout = req.opts.timeout;
    }

    if let (Some(0), Some(file_size)) = (req.opts.transfer_size, file_size) {
        opts.transfer_size = Some(file_size);
    }

    if let (Some(client_window_size), Some(server_window_size)) =
        (config.window_size, req.opts.window_size)
    {
        opts.window_size = Some(min(client_window_size, server_window_size))
    }

    if opts == Opts::default() {
        None
    } else {
        Some(opts)
    }
}
