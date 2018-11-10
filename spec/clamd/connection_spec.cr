require "../spec_helper"

describe Clamd::Connection do
  describe ".connect_unix" do
    it "connects via unix socket" do
      connection = Clamd::Connection.connect_unix(ENV["CLAMD_SOCK_PATH"])
      connection.@connection.should be_a(UNIXSocket)
      connection.ping.should eq("PONG")
      connection.close
    end
  end

  describe ".connect_tcp" do
    it "connects via tcp" do
      connection = Clamd::Connection.connect_tcp(ENV["CLAMD_HOST"], ENV["CLAMD_PORT"].to_i)
      connection.@connection.should be_a(TCPSocket)
      connection.ping.should eq("PONG")
      connection.close
    end
  end

  describe ".new" do
    it "starts an IDSESSION" do
      io = IO::Memory.new
      connection = Clamd::Connection.new(io)
      io.to_s.should eq("zIDSESSION\0")
    end
  end

  describe ".open_unix" do
    it "connects via unix socket" do
      Clamd::Connection.open_unix(ENV["CLAMD_SOCK_PATH"]) do |connection|
        connection.@connection.should be_a(UNIXSocket)
        connection.ping.should eq("PONG")
      end
    end

    it "closes the socket" do
      connection_outside = nil
      Clamd::Connection.open_unix(ENV["CLAMD_SOCK_PATH"]) do |connection|
        connection_outside = connection
        connection.closed?.should be_false
      end
      connection_outside.not_nil!.closed?.should be_true
      connection_outside.not_nil!.@connection.closed?.should be_true
    end

    # TODO: unpend after 0.19.3
    pending "closes the socket when exception is thrown" do
      connection_outside = nil
      begin
        Clamd::Connection.open_unix(ENV["CLAMD_SOCK_PATH"]) do |connection|
          connection_outside = connection
          connection.closed?.should be_false
          raise "clamd test exception"
        end
      rescue ex
        raise ex unless ex.message == "clamd test exception"
      end
      connection_outside.not_nil!.closed?.should be_true
      connection_outside.not_nil!.@connection.closed?.should be_true
    end
  end

  describe ".open_tcp" do
    it "connects via tcp" do
      Clamd::Connection.open_tcp(ENV["CLAMD_HOST"], ENV["CLAMD_PORT"].to_i) do |connection|
        connection.@connection.should be_a(TCPSocket)
        connection.ping.should eq("PONG")
      end
    end

    it "closes the socket" do
      connection_outside = nil
      Clamd::Connection.open_tcp(ENV["CLAMD_HOST"], ENV["CLAMD_PORT"].to_i) do |connection|
        connection_outside = connection
        connection.closed?.should be_false
      end
      connection_outside.not_nil!.closed?.should be_true
      connection_outside.not_nil!.@connection.closed?.should be_true
    end

    # TODO: unpend after 0.19.3
    pending "closes the socket when exception is thrown" do
      connection_outside = nil
      begin
        Clamd::Connection.open_tcp(ENV["CLAMD_HOST"], ENV["CLAMD_PORT"].to_i) do |connection|
          connection_outside = connection
          connection.closed?.should be_false
          raise "clamd test exception"
        end
      rescue ex
        raise ex unless ex.message == "clamd test exception"
      end
      connection_outside.not_nil!.closed?.should be_true
      connection_outside.not_nil!.@connection.closed?.should be_true
    end
  end

  describe "#send" do
    it "sends a command" do
      clamd_connection do |conn|
        conn.send("PING").should eq("PONG")
      end
    end

    it "detects errors" do
      clamd_connection do |conn|
        expect_raises(Clamd::Connection::Error, "Command invalid inside IDSESSION") do
          conn.send("INVALIDCOMMAND")
        end
      end
    end

    it "doesn't detect errors with `detect_error: false`" do
      clamd_connection do |conn|
        conn.send("INVALIDCOMMAND", detect_error: false)
          .should eq("Command invalid inside IDSESSION. ERROR")
      end
    end

    it "raises on connection close" do
      clamd_connection do |conn|
        expect_raises(Clamd::Connection::Error, "Connection closed by clamd") do
          conn.send("END")
        end
      end
    end

    it "yields the connection" do
      clamd_connection do |conn|
        conn.send("PING") do |io|
          io.should be_a(IO)
        end.should eq("PONG")
      end
    end

    it "raises when closed" do
      conn = Clamd::Connection.new(IO::Memory.new)
      conn.close

      expect_raises(Clamd::Connection::Error, "Connection closed") do
        conn.send("FOO")
      end
    end
  end

  describe "#ping" do
    it "responds PONG" do
      clamd_connection do |conn|
        conn.ping.should eq("PONG")
      end
    end

    it "raises when closed" do
      conn = Clamd::Connection.new(IO::Memory.new)
      conn.close

      expect_raises(Clamd::Connection::Error, "Connection closed") do
        conn.ping
      end
    end
  end

  describe "#version" do
    it "responds with the clamav version" do
      clamd_connection do |conn|
        conn.version.should match(/^ClamAV [0-9]+\.[0-9]+\.[0-9]+/)
      end
    end

    it "raises when closed" do
      conn = Clamd::Connection.new(IO::Memory.new)
      conn.close

      expect_raises(Clamd::Connection::Error, "Connection closed") do
        conn.version
      end
    end
  end

  describe "#scan" do
    # Define this flag if clamd has access to the same filesystem this source is hosted on.
    {% if flag?(:clamd_same_fs) %}
      it "scans a virus file" do
        clamd_connection do |conn|
          filename = File.join(__DIR__, "..", "test_file", "eicar")
          result = conn.scan(filename)

          result.filename.should eq(filename)
          result.status.should eq(Clamd::Status::Virus)
          result.signature.should eq("Eicar-Test-File")
        end
      end

      it "scans an empty file" do
        clamd_connection do |conn|
          filename = File.join(__DIR__, "..", "test_file", "empty")
          result = conn.scan(filename)

          result.filename.should eq(filename)
          result.status.should eq(Clamd::Status::Clean)
        end
      end

      it "scans a clean file" do
        clamd_connection do |conn|
          filename = File.join(__DIR__, "..", "test_file", "clean")
          result = conn.scan(filename)

          result.filename.should eq(filename)
          result.status.should eq(Clamd::Status::Clean)
        end
      end
    {% end %}

    it "raises when closed" do
      conn = Clamd::Connection.new(IO::Memory.new)
      conn.close

      expect_raises(Clamd::Connection::Error, "Connection closed") do
        conn.scan("/tmp")
      end
    end
  end

  describe "#scan_stream" do
    it "scans a virus file" do
      clamd_connection do |conn|
        filename = File.join(__DIR__, "..", "test_file", "eicar")
        File.open(filename, "r") do |io|
          result = conn.scan_stream(io)

          result.filename.should eq("stream")
          result.status.should eq(Clamd::Status::Virus)
          result.signature.should match(/eicar.test/i)
        end
      end
    end

    it "scans an empty file" do
      clamd_connection do |conn|
        filename = File.join(__DIR__, "..", "test_file", "empty")
        File.open(filename, "r") do |io|
          result = conn.scan_stream(io)

          result.filename.should eq("stream")
          result.status.should eq(Clamd::Status::Clean)
        end
      end
    end

    it "scans a clean file" do
      clamd_connection do |conn|
        filename = File.join(__DIR__, "..", "test_file", "clean")
        File.open(filename, "r") do |io|
          result = conn.scan_stream(io)

          result.filename.should eq("stream")
          result.status.should eq(Clamd::Status::Clean)
        end
      end
    end

    it "raises when closed" do
      conn = Clamd::Connection.new(IO::Memory.new)
      conn.close

      expect_raises(Clamd::Connection::Error, "Connection closed") do
        conn.scan_stream(IO::Memory.new)
      end
    end
  end

  describe "#close" do
    it "closes the connection" do
      io = IO::Memory.new
      conn = Clamd::Connection.new(io)
      conn.close

      io.closed?.should be_true
      conn.closed?.should be_true

      pointerof(io.@closed).value = false
      io.rewind
      io.gets_to_end.should eq("zIDSESSION\0zEND\0")
    end
  end
end
