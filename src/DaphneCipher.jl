module DaphneCipher
using OffsetArrays
export twist,funSbox,stepp,invStep,left,right
export Daphne,setKey!,encrypt!,decrypt!

# If n has at least 3 bits and k is relatively prime to the number of bits
# in n, this permutation satisfies the strict avalanche criterion.
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

invSbox=copy(sbox)
for i in 0x00:0xff
  invSbox[funSbox(i)]=i
end

function mulOdd(a::Integer,b::Integer)
  a+b+0x2*a*b
end

function mul257(a::Integer,b::Integer)
  a32=convert(Int32,a)+256*(a==0) # a and b are normally UInt8,
  b32=convert(Int32,b)+256*(b==0) # which must be converted to avoid overflow.
  p=(a32*b32)%257
  convert(typeof(a),p%256)
end

invOdd=copy(sbox)
for i in 0x00:0xff
  for j in 0x00:0xff
    if mulOdd(i,j)==0
      invOdd[i]=j
    end
  end
end

inv257=copy(sbox)
for i in 0x00:0xff
  for j in 0x00:0xff
    if mul257(i,j)==1
      inv257[i]=j
    end
  end
end

divOdd(m,n)=mulOdd(m,invOdd[n])
div257(m,n)=mul257(m,inv257[n])
# "step" is in Base and relates to iterators.
stepp(x,l,r)=mulOdd(sbox[mul257(x,l)],r)
invStep(x,l,r)=div257(invSbox[divOdd(x,r)],l)

mutable struct Daphne
  key	::Vector{UInt8}
  sreg	::Vector{UInt8}
  acc	::UInt8
  Daphne()=new([],[],0)
end

function setKey!(d::Daphne,k::Vector{UInt8})
  d.key=copy(k)
  d.sreg=zero(k)
  d.acc=0x00
end

function left(d::Daphne)
  a=d.acc
  for i in reverse(eachindex(d.key))
    a=stepp(a,d.sreg[i],d.key[i])
  end
  a
end

function right(d::Daphne)
  a=d.acc
  for i in eachindex(d.key)
    a=stepp(a,d.key[i],d.sreg[i])
  end
  a
end

function encrypt!(d::Daphne,plain::UInt8)
  crypt=stepp(plain,left(d),right(d))
  d.acc+=plain
  push!(d.sreg,crypt)
  popfirst!(d.sreg)
  crypt
end

function decrypt!(d::Daphne,crypt::UInt8)
  plain=invStep(crypt,left(d),right(d))
  d.acc+=plain
  push!(d.sreg,crypt)
  popfirst!(d.sreg)
  plain
end

function encrypt!(d::Daphne,plain::Vector{UInt8})
  crypt=UInt8[]
  sizehint!(crypt,length(plain))
  for b in plain
    push!(crypt,encrypt!(d,b))
  end
  crypt
end

function decrypt!(d::Daphne,crypt::Vector{UInt8})
  plain=UInt8[]
  sizehint!(plain,length(crypt))
  for b in crypt
    push!(plain,decrypt!(d,b))
  end
  plain
end

end # module DaphneCipher
