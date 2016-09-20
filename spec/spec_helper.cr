require "spec"
require "../src/clamd"

def clamd_tcp
  conn = Clamd::Connection.connect_tcp(ENV["CLAMD_HOST"], ENV["CLAMD_PORT"].to_i)
  begin
    yield conn
  ensure
    conn.close
  end
end

def clamd_unix
  conn = Clamd::Connection.connect_unix(ENV["CLAMD_SOCK_PATH"])
  begin
    yield conn
  ensure
    conn.close
  end
end

def clamd_connection
  if rand > 0.5
    clamd_tcp { |c| yield c }
  else
    clamd_unix { |c| yield c }
  end
end
