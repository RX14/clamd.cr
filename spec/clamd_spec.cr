require "./spec_helper"
require "yaml"

describe Clamd do
  it "has the correct version" do
    version = YAML.parse(File.read(File.join(__DIR__, "..", "shard.yml")))["version"].as_s
    version.should eq(Clamd::VERSION)
  end
end
