#!/usr/bin/ruby
require 'optparse'
require 'socket'
require 'json'
require 'influxdb'

CTRL_CMD_DUMP=[0x01, 0x00, 0x00, 0x00].pack("CCCC")
CTRL_CMD_CLEAR=[0x02, 0x00, 0x00, 0x00].pack("CCCC")
VALUE_KEY = ["size", "count"]
DBNAME  ='pktcaptd0' #XXX set database name
DBSERVER="127.0.0.1" #XXX set database server address (default: localhost)
USERNAME="pktcaptd0" #XXX set user name of the database
PASSWORD="pktcaptd0" #XXX set password of the database


class Command
  attr_accessor :msgs, :cmd
  def initialize(c)
    @msgs = []
    @cmd = c
  end
end

lconf = ARGV.getopts('dS:')
debug = lconf["d"]
sockpath = lconf["S"] || "/var/run/pktcaptd.sock"

dump = Command.new(CTRL_CMD_DUMP)
clear = Command.new(CTRL_CMD_CLEAR)
cmds = [dump, clear]

cmds.each do |c|
  UNIXSocket.open(sockpath) do |s|
    s.write(c.cmd)
    begin
      while true
        c.msgs << s.readline
      end
    rescue EOFError => e
      break;
    end
  end
end


begin
  h = JSON.load(dump.msgs.join(""))
rescue => e
  exit 1
end

auth = {
  :username => USERNAME,
  :password => PASSWORD,
  :host     => DBSERVER,
  :time_precision => "s"
}

influxdb = InfluxDB::Client.new(DBNAME, auth)

exit 1 unless h["flows"].is_a? Array
json_total = h["total_flow"] || 0
array_total = 0
h["flows"].each do |elm|
  next unless elm.is_a? Hash
  array_total += 1
  tags = {}
  values = {}
  elm.each do |k, v|
    if VALUE_KEY.include?(k)
      v = v.to_f if k == "size"
      values[k] = v
    else
      tags[k] = v
    end
  end

  if debug
    puts "#{values}#{tags}"
  end
  data = {:values => values, :tags => tags}
  influxdb.write_point('flows', data)
end

if debug
  puts "JSON total = #{json_total}, Array total = #{array_total}"
end
