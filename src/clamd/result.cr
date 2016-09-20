module Clamd
  struct Result
    getter filename : String
    getter status : Status
    getter signature : String?

    def initialize(@status, @filename, @signature = nil)
    end
  end

  enum Status
    Clean
    Virus
  end
end
