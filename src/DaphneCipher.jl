"""
    DaphneCipher

Daphne is a self-synchronizing byte stream cipher. It takes an arbitrary-length
key and encrypts a stream of bytes in such a way that, if a byte is garbled,
lost, or inserted in the ciphertext, the plaintext will be garbled for the key
length plus a variable number of bytes, usually less than 256, and will then
recover.
"""
module DaphneCipher
using OffsetArrays
export Daphne,setKey!,encrypt!,decrypt!

# If n has at least 3 bits and k is relatively prime to the number of bits
# in n, this permutation satisfies the strict avalanche criterion.
function twist(n::Integer,k::Integer)
  bitrotate(n,count_ones(n)*k)
end

# This is a P-box used to generate the S-box.
# 1 0 0 0 0 0 0 0
# 0 0 0 0 0 0 1 0
# 0 0 0 1 0 0 0 0
# 0 0 0 0 0 0 0 1
# 0 0 0 0 0 1 0 0
# 0 0 1 0 0 0 0 0
# 0 1 0 0 0 0 0 0
# 0 0 0 0 1 0 0 0
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

const sbox=OffsetVector(UInt8[],-1)
for i in 0x00:0xff
  push!(sbox,funSbox(i))
end

const invSbox=copy(sbox)
for i in 0x00:0xff
  invSbox[funSbox(i)]=i
end

# Equivalent to shifting m and n left by 1 with a 1 bit (thus making them odd),
# multiplying, and shifting right (discarding the 1 bit).
function mulOddf(a::Integer,b::Integer)
  a+b+0x2*a*b
end

function mul257f(a::Integer,b::Integer)
  a32=convert(Int32,a)+256*(a==0) # a and b are normally UInt8,
  b32=convert(Int32,b)+256*(b==0) # which must be converted to avoid overflow.
  p=(a32*b32)%257
  convert(typeof(a),p%256)
end

const mulOdd=OffsetMatrix(Matrix{UInt8}(undef,256,256),-1,-1)
const divOdd=OffsetMatrix(Matrix{UInt8}(undef,256,256),-1,-1)
for i in 0x00:0xff
  for j in 0x00:0xff
    mulOdd[i,j]=mulOddf(i,j)
    divOdd[mulOddf(i,j),j]=i
  end
end

const mul257=OffsetMatrix(Matrix{UInt8}(undef,256,256),-1,-1)
const div257=OffsetMatrix(Matrix{UInt8}(undef,256,256),-1,-1)
for i in 0x00:0xff
  for j in 0x00:0xff
    mul257[i,j]=mul257f(i,j)
    div257[mul257f(i,j),j]=i
  end
end

# "step" is in Base and relates to iterators.
stepp(x,l,r)=@inbounds mulOdd[sbox[mul257[x,l]],r]
invStep(x,l,r)=@inbounds div257[invSbox[divOdd[x,r]],l]

"""
    mutable struct Daphne

Contains the key and state of a Daphne stream cipher.
`Daphne()` creates a keyless Daphne; call `setKey!` to set the key.
"""
mutable struct Daphne
  key	::Vector{UInt8}
  sreg	::Vector{UInt8}
  acc	::UInt8
  Daphne()=new([],[],0)
end

"""
    setKey!(d::Daphne,k::Vector{UInt8})

Set the key of a Daphne. `k` should be at least 16 bytes, or 32 bytes to avoid
Grover's algorithm, but longer keys make encryption and decryption slower.
"""
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

"""
    encrypt!(d::Daphne,plain::UInt8)

Encrypt one byte. `d`'s state is changed.
"""
function encrypt!(d::Daphne,plain::UInt8)
  crypt=stepp(plain,left(d),right(d))
  d.acc+=plain
  push!(d.sreg,crypt)
  popfirst!(d.sreg)
  crypt
end

"""
    decrypt!(d::Daphne,crypt::UInt8)

Decrypt one byte. `d`'s state is changed.
"""
function decrypt!(d::Daphne,crypt::UInt8)
  plain=invStep(crypt,left(d),right(d))
  d.acc+=plain
  push!(d.sreg,crypt)
  popfirst!(d.sreg)
  plain
end

"""
    encrypt!(d::Daphne,plain::Vector{UInt8})

Encrypt many bytes. `d` is changed, but `plain` is not; returns the encrypted bytes
in a new `Vector`.
"""
function encrypt!(d::Daphne,plain::Vector{UInt8})
  crypt=UInt8[]
  sizehint!(crypt,length(plain))
  for b in plain
    push!(crypt,encrypt!(d,b))
  end
  crypt
end


"""
    decrypt!(d::Daphne,crypt::Vector{UInt8})

Decrypt many bytes. `d` is changed, but `crypt` is not; returns the decrypted bytes
in a new `Vector`.
"""
function decrypt!(d::Daphne,crypt::Vector{UInt8})
  plain=UInt8[]
  sizehint!(plain,length(crypt))
  for b in crypt
    push!(plain,decrypt!(d,b))
  end
  plain
end

end # module DaphneCipher
