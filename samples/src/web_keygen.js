class Co
{
    constructor(CoCo)
    {
        this.CoCoCo = CoCo.CoCoCo;
        this.CoCoCoCo = CoCo.CoCoCoCoCo();        
        this.CoCoCoCoCoCo = CoCo.CoCoCoCoCo();        
        this.CoCoCoCoCoCoCo = CoCo.CoCoCoCoCo();
    }
    
    
    
    CoCoCoCoCoCoCoCo()
    {
        switch( this.CoCoCoCoCoCo )
        {
            case 1:
                return this.CoCoCo.getUint8(this.CoCoCoCo)*this.CoCoCoCoCoCoCo;
            case 2:
                return this.CoCoCo.getUint16(this.CoCoCoCo)*this.CoCoCoCoCoCoCo;
            case 4:
                return this.CoCoCo.getUint32(this.CoCoCoCo)*this.CoCoCoCoCoCoCo;
        }     
    }
    
    CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCo)
    {        
        switch( this.CoCoCoCoCoCo )
        {
            case 1:
               this.CoCoCo.setUint8(this.CoCoCoCo,CoCoCoCoCoCoCoCoCoCo);
               break;
            case 2:
               this.CoCoCo.setUint16(this.CoCoCoCo,CoCoCoCoCoCoCoCoCoCo);
               break;
            case 4:
               this.CoCoCo.setUint32(this.CoCoCoCo,CoCoCoCoCoCoCoCoCoCo);
               break;
        }
        this.CoCoCoCoCoCoCo = 1;
    }    
}

class CoCoCoCoCoCoCoCoCoCoCo
{
    constructor(CoCo)
    {
        this.CoCoCoCoCoCoCoCoCoCo = CoCo.CoCoCoCoCoCoCoCoCoCoCoCo();
    }
    

    CoCoCoCoCoCoCoCo()
    {
        return this.CoCoCoCoCoCoCoCoCoCo;       
    }
    
    CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCo)
    {
    }
}

class CoCoCoCoCoCoCoCoCoCoCoCoCo
{
    constructor(CoCo)
    {      
        this.CoCoCoCo = 0;
        
        var CoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCo.CoCoCoCoCo(); 
        
        while( CoCoCoCoCoCoCoCoCoCoCoCoCoCo-- )
        {
            this.CoCoCoCo += CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo().CoCoCoCoCoCoCoCo();            
        }
        
        this.CoCoCoCo &= 0xFFFFFFFF;
        
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo;
        this.CoCoCo = CoCo.CoCoCo;
    }
}

class CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo extends CoCoCoCoCoCoCoCoCoCoCoCoCo
{


    CoCoCoCoCoCoCoCo()
    {          
        return this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.getUint8(this.CoCoCoCo);
    }
    
    CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCo)
    {
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.setUint8(this.CoCoCoCo,CoCoCoCoCoCoCoCoCoCo);
    }        
}

class CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo extends CoCoCoCoCoCoCoCoCoCoCoCoCo
{



    CoCoCoCoCoCoCoCo()
    {          
        return this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.getUint32(this.CoCoCoCo);
    }
    
    CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCo)
    {
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.setUint32(this.CoCoCoCo,CoCoCoCoCoCoCoCoCoCo);
    }        
}

class CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo
{
    constructor(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo)
    {
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = new DataView(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.buffer);
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = 0;
        this.CoCoCo = new DataView(new ArrayBuffer(32));
        var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.length;
        this.CoCoCo.setInt32(16,CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
        
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = false;
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = false;        
    }
    
    
    CoCoCoCoCoCoCoCoCoCoCoCo()
    {
        var CoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.getUint32(this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo += 4;
        return CoCoCoCoCoCoCoCoCoCo;        
    }
    
    CoCoCoCoCo()
    {
        var CoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.getUint8(this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo++;
        return CoCoCoCoCoCoCoCoCoCo;
    }
    
    CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo()
    {
        var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCo();
        switch(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo )
        {
            case 1:
                return new Co(this);                
            case 2:
                return new CoCoCoCoCoCoCoCoCoCoCo(this);
            case 3:
                return new CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(this);
            case 4:
                return new CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(this);
        }
        return null;
    }
    
    
    CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCo)
    {
        var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCo.getInt32(16) - 4;        
        this.CoCoCo.setInt32(16,CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.setUint32(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo,CoCoCoCoCoCoCoCoCoCo)
        return CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo;
    }
    
    CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo()
    {
        var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCo.getInt32(16);
        var CoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.getUint32(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
        CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo += 4;
        this.CoCoCo.setInt32(16,CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);        
        return CoCoCoCoCoCoCoCoCoCo;
    }


    CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo()
    {
        var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCo();
        switch(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo)
        {
            case 4:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();
                
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo;
                break;
            case 2:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo());
                break;
            case 8:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();
                break;
            case 10:            
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo()>>>0);
                                
                break;
            case 5:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo() + CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();
                                
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = new Boolean(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo>>32);

                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
                break;
            case 18:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo() >>> CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();
                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);     
                break;
            case 11:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo() ^ CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();
                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);             
                break;
            case 3:        
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo() + ((~CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo()) + 1);
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = new Boolean(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo>>32);
                    
                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
                break;
            case 15:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo;
                break;
            case 14:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                                
                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
                break;
            case 17:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo() & CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();                
                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
                break;
            case 9:        
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();     

                
                if(this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo == false)                
                {
                    this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();    
                }                
                break;
            case 1:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo());
                break;
            case 6:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();                
                
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = (CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo() == CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo());
                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo() + ((~CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo()) + 1);
                this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = new Boolean(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo>>32);
                break;
            case 7:                                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();  
                
                if(this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo == false)                
                {
                    this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();    
                }
                break;
            case 13:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo() | CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();                
                CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
                break;
            case 16:                
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                
                if(this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo == true)          
                {
                    this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();    
                }            
                break;
            case 12:
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
                
                var CoCoCoCoCoCoCoCoCoCo = (this.CoCoCo.getInt32(8) << 32) | this.CoCoCo.getInt32(0);
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCo / CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();
                this.CoCoCo.setInt32(0,CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
                var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCo % CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.CoCoCoCoCoCoCoCo();
                this.CoCoCo.setInt32(8,CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);                
                break;
        }
    }
}

function GetFlag(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo)
{
    var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = new Uint8Array([1,1,20,4,1,2,1,20,4,1,1,16,4,1,3,1,16,4,1,2,0,0,0,44,1,1,24,4,1,2,3,2,2,255,255,255,212,1,20,4,1,2,0,0,0,115,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,1,2,0,0,0,20,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,2,2,0,0,0,32,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,3,2,0,0,0,23,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,4,2,0,0,0,2,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,5,2,0,0,0,98,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,6,2,0,0,0,42,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,7,2,0,0,0,119,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,8,2,0,0,0,121,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,9,2,0,0,0,29,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,10,2,0,0,0,33,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,11,2,0,0,0,113,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,12,2,0,0,0,112,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,13,2,0,0,0,103,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,14,2,0,0,0,94,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,15,2,0,0,0,6,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,16,2,0,0,0,0,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,17,2,0,0,0,30,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,18,2,0,0,0,91,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,19,2,0,0,0,113,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,20,2,0,0,0,125,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,21,2,0,0,0,103,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,22,2,0,0,0,95,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,23,2,0,0,0,113,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,24,2,0,0,0,123,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,25,2,0,0,0,111,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,26,2,0,0,0,80,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,27,2,0,0,0,2,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,28,2,0,0,0,119,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,29,2,0,0,0,103,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,30,2,0,0,0,90,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,31,2,0,0,0,115,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,32,2,0,0,0,9,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,33,2,0,0,0,25,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,34,2,0,0,0,39,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,35,2,0,0,0,1,2,3,3,2,255,255,255,212,1,20,4,1,2,0,0,0,36,2,0,0,0,5,1,2,0,0,0,8,2,1,0,4,1,4,2,2,0,0,0,8,1,20,4,1,1,1,0,4,1,1,2,18,52,86,120,4,2,0,0,4,199,5,1,16,4,1,2,0,0,0,12,6,1,0,4,1,2,51,229,174,64,7,2,0,0,4,164,2,4,2,2,255,255,255,252,1,20,4,1,2,0,0,0,0,2,4,2,2,255,255,255,252,1,20,4,1,2,0,0,0,0,8,2,0,0,3,217,2,1,4,4,1,4,2,2,255,255,255,252,1,20,4,1,5,1,4,4,1,2,0,0,0,1,2,4,2,2,255,255,255,252,1,20,4,1,1,4,4,1,6,4,2,2,255,255,255,252,1,20,4,1,2,0,0,0,37,9,2,0,0,4,149,2,1,8,4,1,4,2,2,255,255,255,252,1,20,4,1,10,1,4,4,1,3,3,2,255,255,255,212,1,20,4,1,1,8,4,1,2,1,0,4,1,4,2,2,255,255,255,252,1,20,4,1,11,1,8,4,1,1,8,4,1,2,1,24,4,1,2,0,0,0,8,12,1,24,4,1,2,1,0,4,1,4,2,2,0,0,0,8,1,20,4,1,10,1,8,4,1,3,2,1,0,4,1,1,8,4,1,11,1,4,4,1,1,8,4,1,2,1,0,4,1,4,2,2,0,0,0,12,1,20,4,1,5,1,0,4,1,4,2,2,255,255,255,252,1,20,4,1,2,3,1,1,0,4,1,1,7,1,1,8,2,0,0,3,175,11,1,0,4,1,1,0,4,1,8,2,0,0,4,174,13,1,0,4,1,2,255,255,255,255,14,1,24,4,1,2,1,16,4,1,1,20,4,1,14,1,20,4,1,15,2,0,0,0,0,1,1,20,4,1,2,1,20,4,1,1,16,4,1,3,1,16,4,1,2,0,0,4,8,2,4,2,2,255,255,251,248,1,20,4,1,2,0,0,0,0,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,4,2,119,7,48,150,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,8,2,238,14,97,44,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,12,2,153,9,81,186,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,16,2,7,109,196,25,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,20,2,112,106,244,143,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,24,2,233,99,165,53,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,28,2,158,100,149,163,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,32,2,14,219,136,50,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,36,2,121,220,184,164,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,40,2,224,213,233,30,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,44,2,151,210,217,136,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,48,2,9,182,76,43,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,52,2,126,177,124,189,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,56,2,231,184,45,7,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,60,2,144,191,29,145,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,64,2,29,183,16,100,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,68,2,106,176,32,242,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,72,2,243,185,113,72,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,76,2,132,190,65,222,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,80,2,26,218,212,125,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,84,2,109,221,228,235,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,88,2,244,212,181,81,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,92,2,131,211,133,199,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,96,2,19,108,152,86,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,100,2,100,107,168,192,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,104,2,253,98,249,122,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,108,2,138,101,201,236,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,112,2,20,1,92,79,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,116,2,99,6,108,217,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,120,2,250,15,61,99,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,124,2,141,8,13,245,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,128,2,59,110,32,200,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,132,2,76,105,16,94,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,136,2,213,96,65,228,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,140,2,162,103,113,114,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,144,2,60,3,228,209,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,148,2,75,4,212,71,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,152,2,210,13,133,253,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,156,2,165,10,181,107,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,160,2,53,181,168,250,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,164,2,66,178,152,108,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,168,2,219,187,201,214,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,172,2,172,188,249,64,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,176,2,50,216,108,227,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,180,2,69,223,92,117,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,184,2,220,214,13,207,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,188,2,171,209,61,89,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,192,2,38,217,48,172,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,196,2,81,222,0,58,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,200,2,200,215,81,128,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,204,2,191,208,97,22,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,208,2,33,180,244,181,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,212,2,86,179,196,35,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,216,2,207,186,149,153,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,220,2,184,189,165,15,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,224,2,40,2,184,158,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,228,2,95,5,136,8,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,232,2,198,12,217,178,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,236,2,177,11,233,36,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,240,2,47,111,124,135,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,244,2,88,104,76,17,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,248,2,193,97,29,171,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,0,252,2,182,102,45,61,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,0,2,118,220,65,144,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,4,2,1,219,113,6,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,8,2,152,210,32,188,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,12,2,239,213,16,42,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,16,2,113,177,133,137,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,20,2,6,182,181,31,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,24,2,159,191,228,165,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,28,2,232,184,212,51,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,32,2,120,7,201,162,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,36,2,15,0,249,52,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,40,2,150,9,168,142,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,44,2,225,14,152,24,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,48,2,127,106,13,187,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,52,2,8,109,61,45,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,56,2,145,100,108,151,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,60,2,230,99,92,1,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,64,2,107,107,81,244,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,68,2,28,108,97,98,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,72,2,133,101,48,216,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,76,2,242,98,0,78,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,80,2,108,6,149,237,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,84,2,27,1,165,123,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,88,2,130,8,244,193,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,92,2,245,15,196,87,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,96,2,101,176,217,198,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,100,2,18,183,233,80,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,104,2,139,190,184,234,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,108,2,252,185,136,124,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,112,2,98,221,29,223,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,116,2,21,218,45,73,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,120,2,140,211,124,243,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,124,2,251,212,76,101,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,128,2,77,178,97,88,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,132,2,58,181,81,206,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,136,2,163,188,0,116,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,140,2,212,187,48,226,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,144,2,74,223,165,65,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,148,2,61,216,149,215,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,152,2,164,209,196,109,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,156,2,211,214,244,251,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,160,2,67,105,233,106,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,164,2,52,110,217,252,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,168,2,173,103,136,70,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,172,2,218,96,184,208,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,176,2,68,4,45,115,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,180,2,51,3,29,229,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,184,2,170,10,76,95,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,188,2,221,13,124,201,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,192,2,80,5,113,60,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,196,2,39,2,65,170,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,200,2,190,11,16,16,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,204,2,201,12,32,134,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,208,2,87,104,181,37,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,212,2,32,111,133,179,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,216,2,185,102,212,9,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,220,2,206,97,228,159,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,224,2,94,222,249,14,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,228,2,41,217,201,152,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,232,2,176,208,152,34,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,236,2,199,215,168,180,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,240,2,89,179,61,23,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,244,2,46,180,13,129,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,248,2,183,189,92,59,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,1,252,2,192,186,108,173,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,0,2,237,184,131,32,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,4,2,154,191,179,182,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,8,2,3,182,226,12,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,12,2,116,177,210,154,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,16,2,234,213,71,57,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,20,2,157,210,119,175,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,24,2,4,219,38,21,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,28,2,115,220,22,131,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,32,2,227,99,11,18,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,36,2,148,100,59,132,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,40,2,13,109,106,62,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,44,2,122,106,90,168,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,48,2,228,14,207,11,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,52,2,147,9,255,157,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,56,2,10,0,174,39,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,60,2,125,7,158,177,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,64,2,240,15,147,68,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,68,2,135,8,163,210,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,72,2,30,1,242,104,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,76,2,105,6,194,254,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,80,2,247,98,87,93,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,84,2,128,101,103,203,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,88,2,25,108,54,113,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,92,2,110,107,6,231,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,96,2,254,212,27,118,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,100,2,137,211,43,224,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,104,2,16,218,122,90,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,108,2,103,221,74,204,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,112,2,249,185,223,111,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,116,2,142,190,239,249,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,120,2,23,183,190,67,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,124,2,96,176,142,213,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,128,2,214,214,163,232,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,132,2,161,209,147,126,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,136,2,56,216,194,196,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,140,2,79,223,242,82,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,144,2,209,187,103,241,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,148,2,166,188,87,103,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,152,2,63,181,6,221,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,156,2,72,178,54,75,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,160,2,216,13,43,218,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,164,2,175,10,27,76,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,168,2,54,3,74,246,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,172,2,65,4,122,96,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,176,2,223,96,239,195,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,180,2,168,103,223,85,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,184,2,49,110,142,239,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,188,2,70,105,190,121,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,192,2,203,97,179,140,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,196,2,188,102,131,26,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,200,2,37,111,210,160,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,204,2,82,104,226,54,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,208,2,204,12,119,149,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,212,2,187,11,71,3,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,216,2,34,2,22,185,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,220,2,85,5,38,47,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,224,2,197,186,59,190,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,228,2,178,189,11,40,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,232,2,43,180,90,146,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,236,2,92,179,106,4,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,240,2,194,215,255,167,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,244,2,181,208,207,49,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,248,2,44,217,158,139,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,2,252,2,91,222,174,29,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,0,2,155,100,194,176,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,4,2,236,99,242,38,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,8,2,117,106,163,156,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,12,2,2,109,147,10,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,16,2,156,9,6,169,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,20,2,235,14,54,63,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,24,2,114,7,103,133,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,28,2,5,0,87,19,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,32,2,149,191,74,130,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,36,2,226,184,122,20,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,40,2,123,177,43,174,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,44,2,12,182,27,56,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,48,2,146,210,142,155,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,52,2,229,213,190,13,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,56,2,124,220,239,183,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,60,2,11,219,223,33,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,64,2,134,211,210,212,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,68,2,241,212,226,66,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,72,2,104,221,179,248,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,76,2,31,218,131,110,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,80,2,129,190,22,205,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,84,2,246,185,38,91,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,88,2,111,176,119,225,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,92,2,24,183,71,119,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,96,2,136,8,90,230,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,100,2,255,15,106,112,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,104,2,102,6,59,202,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,108,2,17,1,11,92,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,112,2,143,101,158,255,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,116,2,248,98,174,105,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,120,2,97,107,255,211,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,124,2,22,108,207,69,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,128,2,160,10,226,120,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,132,2,215,13,210,238,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,136,2,78,4,131,84,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,140,2,57,3,179,194,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,144,2,167,103,38,97,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,148,2,208,96,22,247,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,152,2,73,105,71,77,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,156,2,62,110,119,219,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,160,2,174,209,106,74,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,164,2,217,214,90,220,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,168,2,64,223,11,102,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,172,2,55,216,59,240,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,176,2,169,188,174,83,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,180,2,222,187,158,197,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,184,2,71,178,207,127,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,188,2,48,181,255,233,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,192,2,189,189,242,28,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,196,2,202,186,194,138,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,200,2,83,179,147,48,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,204,2,36,180,163,166,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,208,2,186,208,54,5,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,212,2,205,215,6,147,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,216,2,84,222,87,41,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,220,2,35,217,103,191,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,224,2,179,102,122,46,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,228,2,196,97,74,184,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,232,2,93,104,27,2,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,236,2,42,111,43,148,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,240,2,180,11,190,55,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,244,2,195,12,142,161,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,248,2,90,5,223,27,2,4,3,2,255,255,251,248,1,20,4,1,2,0,0,3,252,2,45,2,239,141,2,1,0,4,1,4,2,2,0,0,0,12,1,20,4,1,2,4,2,2,255,255,255,252,1,20,4,1,1,0,4,1,2,1,4,4,1,4,2,2,0,0,0,8,1,20,4,1,11,1,4,4,1,2,255,255,255,255,2,4,2,2,0,0,0,8,1,20,4,1,1,4,4,1,2,1,8,4,1,4,2,2,0,0,0,16,1,20,4,1,2,4,2,2,255,255,255,248,1,20,4,1,1,8,4,1,2,1,0,4,1,4,2,2,0,0,0,16,1,20,4,1,3,1,0,4,1,2,0,0,0,1,2,4,2,2,0,0,0,16,1,20,4,1,1,0,4,1,6,4,2,2,255,255,255,248,1,20,4,1,2,0,0,0,0,16,2,0,0,28,40,2,1,4,4,1,4,2,2,255,255,255,252,1,20,4,1,10,1,8,4,1,3,1,1,4,4,1,11,1,8,4,1,4,2,2,0,0,0,8,1,20,4,1,17,1,8,4,1,2,0,0,0,255,2,1,0,4,1,4,2,2,0,0,0,8,1,20,4,1,18,1,0,4,1,2,0,0,0,8,11,1,0,4,1,4,3,2,255,255,251,248,1,20,4,1,1,8,4,4,2,4,2,2,0,0,0,8,1,20,4,1,1,0,4,1,2,1,4,4,1,4,2,2,255,255,255,252,1,20,4,1,5,1,4,4,1,2,0,0,0,1,2,4,2,2,255,255,255,252,1,20,4,1,1,4,4,1,8,2,0,0,27,36,2,1,0,4,1,4,2,2,0,0,0,8,1,20,4,1,11,1,0,4,1,2,255,255,255,255,2,1,16,4,1,1,20,4,1,14,1,20,4,1,15,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
    var CoCo = new CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
    var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCo.CoCoCo.getInt32(16) - 38;        
    CoCo.CoCoCo.setInt32(16,CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
    var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo;
    var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCo.CoCoCo.getInt32(16) - 8;        
    CoCo.CoCoCo.setInt32(16,CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
    var CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo;

    CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.set(new TextEncoder("utf-8").encode(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo),CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);

    CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
    CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo);
    CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo(0xFFFFFFFF);

    try
    {
        while(CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo != 0xFFFFFFFF)
        {
            CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo();
        }
    }
    catch(e)
    {    
    }

    if ( CoCo.CoCoCo.getInt32(0) >= 0 )
        return new TextDecoder("utf-8").decode(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo.subarray(CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo,CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo + 37));
    
    return "Failed";
}

password = "EnterPassword"
console.log(GetFlag(password));
