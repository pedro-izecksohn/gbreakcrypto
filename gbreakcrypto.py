import random

class Cursor:
    def __init__(self,i:int):
        self.x=i%4
        self.y=i>>2
        assert(self.y<4)
    def index(self):
        return (self.y*4)+self.x
    def __eq__(self,other):
        return (self.x==other.x) and (self.y==other.y)

def insToStr(instructions):
    ret=""
    for _ in range(6):
        i=instructions%4
        instructions=(instructions>>2)
        ret+=str(i)
    return ret

def instructionsRevert(orig:int):
    #print(f"Reverting instructions {insToStr(orig)} to ",end="")
    ret=0
    for ii in range(6):
        ci=orig%4
        orig=orig>>2
        if ci==0:
            oi=2
        elif ci==2:
            oi=0
        elif ci==1:
            oi=3
        elif ci==3:
            oi=1
        ret=(ret<<2)+oi
    #print(insToStr(ret))
    return ret

def revertByte(b):
    ret=0
    for i in range(8):
        ret=(ret<<1)+(b%2)
        b=b>>1
    return ret

def shortToBytesList(s):
    ret=[s%256, s>>8]
    return ret

def pwGetCursor(pw):
    i=pw%16
    return Cursor(i)

def pwGetInstructions(pw):
    return pw>>4

class Block:
    def __init__(self,ba:bytearray):
        self.bits=[]
        for byte in ba:
            for i in range(8):
                self.bits.append((byte>>i)%2)
    def toBytearray(self)->bytearray:
        ret=bytearray()
        b=0
        for bi, bit in enumerate (self.bits):
            b=(b<<1)+bit
            if bi==7:
                ret.append(revertByte(b))
                b=0
        ret.append(revertByte(b))
        return ret
    def toHex (self):
        bl=self.toBytearray()
        i=(bl[0]*256)+bl[1]
        return hex(i)[2:]
    def __str__(self):
        return self.toHex()
    @classmethod
    def fromHex (clazz,s):
        i=int(s,16)
        ba=bytearray()
        ba.append(i//256)
        ba.append(i%256)
        return clazz(ba)
    def xor (self, ba):
        sb=self.toBytearray()
        sb[0]=sb[0]^ba[0]
        sb[1]=sb[1]^ba[1]
        self.__init__(sb)
    def mix (self, cursor:Cursor, instructions:int):
        for ii in range (6):
            ci=instructions%4
            instructions=instructions>>2
            if ci==0:
                ox=cursor.x+1
                if ox==4:
                    ox=0
                oy=cursor.y
            elif ci==1:
                oy=cursor.y-1
                if oy==-1:
                    oy=3
                ox=cursor.x
            elif ci==2:
                ox=cursor.x-1
                if ox==-1:
                    ox=3
                oy=cursor.y
            elif ci==3:
                oy=cursor.y+1
                if oy==4:
                    oy=0
                ox=cursor.x
            oi=(oy*4)+ox
            ti=cursor.index()
            self.bits[ti],self.bits[oi]=self.bits[oi],self.bits[ti]
            cursor.x=ox
            cursor.y=oy
    def encrypt (self, pw, cursor):
        #print (f"Encrypting {self} ({cursor.index()}) to ",end="")
        self.mix(cursor,pwGetInstructions(pw))
        self.xor(shortToBytesList(pw))
        #print(f"{self} ({cursor.index()})")
    def decrypt(self,pw,cursor):
        #print (f"Decrypting {self} ({cursor.index()}) to ",end="")
        self.xor(shortToBytesList(pw))
        self.mix(cursor,instructionsRevert(pwGetInstructions(pw)))
        #print(f"{self} ({cursor.index()})")

def strToLOB(s:str):
    ba=bytearray(s,"UTF-8")
    if (len(ba)%2)==1:
        h=128+random.randint(0,127)
        ba.insert(0,h)
    else:
        ba.insert(0,random.randint(0,255))
        ba.insert(0,random.randint(0,127))
    ret=[]
    for i in range(0,len(ba),2):
        ret.append(Block(ba[i:i+2]))
    return ret

def lobToStr(lob):
    ba=bytearray()
    for block in lob:
        ba.extend(block.toBytearray())
    #print(ba)
    if ba[0]&128:
        ba=ba[1:]
    else:
        ba=ba[2:]
    return ba.decode("UTF-8")
        
def encrypt (text:str,pw:int)->str:
    lob=strToLOB(text)
    cursor=pwGetCursor(pw)
    for block in lob:
        block.encrypt(pw,cursor)
    lastByte=(pw>>12)^cursor.index()
    ret=""
    for block in lob:
        ret+=block.toHex()+","
    ret+=hex(lastByte)[2:]
    return ret

def decrypt (text:str,pw:int)->str:
    l=text.split(",")
    lastByte=int(l[-1],16)^(pw>>12)
    cursor=Cursor(lastByte)
    m=[]
    for i in range(len(l)-1):
        m.append(Block.fromHex(l[i]))
    for block in reversed(m):
        block.decrypt(pw,cursor)
    oc=pwGetCursor(pw)
    if not cursor.__eq__(oc):
        return None
    #print ("cursor is ok.")
    ret=lobToStr(m)
    return ret

def bruteForce (text, hint):
    for pw in range(0x10000):
        try:
            ret=decrypt(text,pw)
            if not ret:
                continue
            if hint in ret:
                return ret
        except:
            pass

def main():
    ifilename=input("Entre o nome do arquivo de origem: ")
    ifile=open(ifilename,"r")
    ofilename=input("Entre o nome do arquivo de destino: ")
    ofile=open(ofilename,"x")
    text=ifile.read()
    ifile.close()
    ua=input("Digite c para criptografar ou d para decifrar: ")
    if ua.lower()=='c':
        senha=int(input("Digite a senha numérica: "))
        if (0x10000 <= senha) or (senha < 0):
            print ("Senha inválida.")
            exit()
        e=encrypt(text,senha)
        ofile.write(e)
        ofile.close()
        exit()
    elif ua.lower()=='d':
        senha=input("Digite a senha: ")
        if senha:
            ofile.write(decrypt(text,int(senha)))
            ofile.close()
            exit()
        else:
            dica=input("Digite uma palavra do texto plano: ")
            plain=bruteForce(text,dica)
            if not plain:
                print("Não consegui descobrir a senha.")
                exit()
            ofile.write(plain)
            ofile.close()
            exit()
    else:
        print("Opção inválida.")

if __name__=="__main__":
    main()
