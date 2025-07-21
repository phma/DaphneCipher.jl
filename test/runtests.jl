using DaphneCipher,Test,Printf

zerodaph=Daphne()
setKey!(zerodaph,fill(0x0,16))
zcrypt=encrypt!(zerodaph,fill(0x0,256))

squaredaph=Daphne()
setKey!(squaredaph,map(x->x^2,0x0:0xf))
sqcrypt=encrypt!(squaredaph,collect(0x0:0xff))

setKey!(squaredaph,map(x->x^2,0x0:0xf))
sqdecrypt=decrypt!(squaredaph,sqcrypt)

resynccrypt=copy(sqcrypt)
resynccrypt[1]=2
setKey!(squaredaph,map(x->x^2,0x0:0xf))
resyncdecrypt=decrypt!(squaredaph,resynccrypt)

function printSquare(v::Vector{UInt8})
  col=0
  for n in v
    @printf "%02x " n
    col+=1
    if col%16==0
      println()
    end
  end
end

function every17(v::Vector{T}) where T
  ret=T[]
  for i in 1:17:length(v)
    push!(ret,v[i])
  end
  ret
end

println("Encrypt all 0s with all 0s")
printSquare(zcrypt)
@test every17(zcrypt)==[0x2b,0x6d,0xbb,0x43,0x6c,0xc9,0x2e,0xe1,0x97,0x33,0xc9,0x7e,0x94,0x90,0x9e,0xe3]

println("Encrypt 0:255 with squares")
printSquare(sqcrypt)
@test every17(sqcrypt)==[0x59,0xde,0xfd,0xb4,0xaa,0xad,0x7d,0x1d,0x68,0x35,0xa7,0x78,0xe9,0x51,0x9b,0x2e]

println("Decrypt the above")
printSquare(sqdecrypt)
@test sqdecrypt==collect(0x00:0xff)

println("Demonstrate resynchronization")
printSquare(resyncdecrypt)
@test every17(resyncdecrypt)==[0x69,0xe7,0x23,0x78,0x74,0x26,0x47,0x54,0x64,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]
