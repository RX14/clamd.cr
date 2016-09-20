require "socket"

class Clamd::Connection
  # Exception representing an error in the clamd protocol.
  class Error < Exception
  end

  @connection : IO
  @counter : Int32 = 0

  def self.connect_unix(socket_path)
    new(UNIXSocket.new(socket_path))
  end

  def self.connect_tcp(host, port)
    new(TCPSocket.new(host, port))
  end

  def initialize(@connection)
    connection.sync = true if connection.is_a? IO::Buffered
    connection << "zIDSESSION\0"
  end

  def self.open_unix(socket_path)
    connection = connect_unix(socket_path)
    begin
      yield connection
    ensure
      connection.close
    end
  end

  def self.open_tcp(host, port)
    connection = connect_tcp(host, port)
    begin
      yield connection
    ensure
      connection.close
    end
  end

  def send(command, detect_error = true)
    send(command, detect_error) { }
  end

  def send(command, detect_error = true)
    error "Connection closed" if @connection.closed?

    @connection << "z#{command}\0"
    yield @connection

    @counter += 1

    # Read reply counter
    id = @connection.gets(':').try { |str| str[0...-1].to_i }
    error "Connection closed by clamd" unless id
    error "Counter out of sync" if @counter != id

    # Read space after counter
    error "Parse error" if @connection.read_byte != ' '.ord

    # Read response
    reply = @connection.gets('\0').try &.chomp('\0')
    error "Connection closed by clamd" unless reply

    error reply.gsub(/\.? ?ERROR$/, "") if detect_error && reply.ends_with? "ERROR"

    reply
  end

  def ping
    send "PING"
  end

  def version
    send "VERSION"
  end

  def scan(file_path)
    res = send "SCAN #{file_path}"
    interpret_scan res
  end

  def scan_stream(io)
    res = send("INSTREAM") do |connection|
      buf = uninitialized UInt8[8192]

      while true
        chunk_size = io.read(buf.to_slice).to_u32
        connection.write_bytes(chunk_size, IO::ByteFormat::NetworkEndian)
        connection.write(buf.to_slice[0, chunk_size])
        break if chunk_size == 0 # Last chunk should be 0 bytes
      end
    end

    interpret_scan res
  end

  def stats
    send "STATS"
  end

  private def error(msg)
    close
    raise Connection::Error.new(msg)
  end

  private def interpret_scan(scan_result)
    colon_index = scan_result.rindex(':')
    error "Cannot interpret scan result #{scan_result.inspect}" unless colon_index

    filename = scan_result[0...colon_index]
    file_status = scan_result[(colon_index + 2)..-1]

    if file_status.ends_with? "FOUND"
      signature = file_status[0...-(" FOUND".size)]
      Result.new(Status::Virus, filename, signature)
    elsif file_status.ends_with? "OK"
      Result.new(Status::Clean, filename)
    else
      error "Cannot interpret scan result #{scan_result.inspect}"
    end
  end

  def close
    return if closed?
    @connection << "zEND\0" rescue nil # This can fail if the connection was closed by clamd
    @connection.close
  end

  def closed?
    @connection.closed?
  end
end
