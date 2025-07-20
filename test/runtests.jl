using DaphneCipher,Test

zerodaph=Daphne()
setKey!(zerodaph,fill(0x0,16))
zcrypt=encrypt!(zerodaph,fill(0x0,256))

squaredaph=Daphne()
setKey!(squaredaph,map(x->x^2,0x0:0xf))
sqcrypt=encrypt!(squaredaph,collect(0x0:0xff))
