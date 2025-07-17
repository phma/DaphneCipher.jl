module DaphneCipher
using OffsetArrays
export twist,funSbox

function twist(n::Integer,k::Integer)
  bitrotate(n,count_ones(n)*k)
end

function shuffle(n::UInt8)
  bitrotate(n&0x54,3)|
  bitrotate(n&0x28,7)|
  bitrotate(n&0x02,5)|
  bitrotate(n&0x80,4)|
  (n&0x01)
end

function funSbox(n::UInt8)
  0x6e⊻shuffle(twist(n⊻0x25,-1))
end

sbox=OffsetVector(UInt8[],-1)
for i in 0x00:0xff
  push!(sbox,funSbox(i))
end

end # module DaphneCipher
