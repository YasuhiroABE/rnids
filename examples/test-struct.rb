class TEST
  def initialize
    @data = Struct.new("IDMEFData",:impact,:saddr,:sport,:daddr,:dport)
  end

  def create_data
    return @data.new
  end

  def insert(data,content)
    data.impact = content
  end
end


test = TEST.new
data = test.create_data
test.insert(data,"TEST2")


p data
