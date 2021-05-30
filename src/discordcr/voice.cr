require "./mappings/vws"

module Discord
  class VoiceClient
    @ssrc_user_map = Hash(UInt32, Snowflake).new

    def on_receiving(&handler : Bytes, Snowflake?, UInt16, UInt32 ->) # should be called after ready
      # start receiving voice data, spawn a thread to loop it
      spawn do
        loop do
          begin
            payload, ssrc, sequence, timestamp = @udp.receive_audio
            user_id = @ssrc_user_map[ssrc]?
            if user_id
              handler.call(payload, user_id, sequence, timestamp)
            else
            end
          rescue ex
            puts ex.inspect
          end
        end
      end
    end

    def on_message(packet : Discord::WebSocket::Packet)
      case packet.opcode
      when OP_SPEAKING
        Log.debug { "(voice-receving) VWS packet received: #{packet} #{packet.data.to_s}" }

        payload = VWS::SpeakingPayload.from_json(packet.data)
        @ssrc_user_map[payload.ssrc] = payload.user_id
        #on_speaking(payload)
      else
        previous_def # run original definition
      end
    end
  end

  class VoiceUDP
    @buf = Bytes.new(1920)

    def receive_audio
      bytes_read, client_addr = @socket.receive(@buf)
      buf = @buf[0, bytes_read].dup
      header = buf[0, 12]
      sequence = IO::ByteFormat::BigEndian.decode(UInt16, header[2, 2])
      timestamp = IO::ByteFormat::BigEndian.decode(UInt32, header[4, 4])
      ssrc = IO::ByteFormat::BigEndian.decode(UInt32, header[8, 4])
      nonce, enc_data = case @mode
                        when "xsalsa20_poly1305" # nonce = rtp header
                          { header, buf + 12 }
                        when "xsalsa20_poly1305_suffix"
                          { buf[-24..-1], buf[12...-24] }
                        when "xsalsa20_poly1305_lite"
                          { buf[-4..-1], buf[12...-4] }
                        else
                          { Bytes.empty, Bytes.empty }
                        end
      data = decrypt_audio(nonce, enc_data)
      if data.empty?
        { Bytes.empty, 0_u32, 0_u16, 0_u32 }
      else
        has_extension = (header[0] & 0b10000) != 0
        cc = header[0] & 0b1111;
        data += cc * 4 if cc > 0
        if has_extension
          l = IO::ByteFormat::BigEndian.decode(UInt16, data[2, 2])
          data += 4 + l * 4
          while data[0] == 0
            data += 1
          end
        end
        { data, ssrc, sequence, timestamp }
      end
    end

    private def decrypt_audio(nonce : Bytes, buf : Bytes) : Bytes
      raise "No secret key was set!" unless @secret_key

      sodium_nonce = Bytes.new(24, 0_u8)
      nonce.copy_to(sodium_nonce)

      # Sodium constants
      zero_bytes = Sodium.crypto_secretbox_xsalsa20poly1305_zerobytes
      box_zero_bytes = Sodium.crypto_secretbox_xsalsa20poly1305_boxzerobytes

      # Prepend the buf with box_zero_bytes zero bytes
      c = Bytes.new(buf.size + box_zero_bytes, 0_u8)
      buf.copy_to(c + box_zero_bytes)

      # Create a buffer for the message
      message = Bytes.new(c.size)

      # Encrypt
      ret_code = Sodium.crypto_secretbox_xsalsa20poly1305_open(message, c, c.bytesize, sodium_nonce, @secret_key.not_nil!)
      return Bytes.empty if ret_code == -1

      # The resulting message buffer has zero_bytes zero bytes prepended;
      # we don't want them in the result, so move the slice forward by that many
      # bytes
      message + zero_bytes
    end
  end
end
