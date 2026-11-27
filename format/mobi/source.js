// A Blob-like, read-only view of a single authenticated, versioned book.
// The decoder asks for records; aligned blocks avoid one request per record.
const BLOCK=64*1024, BLOCKS=128, BATCH=8, MAX_SOURCE=100*1024*1024;
export class BookSourceError extends Error {
    constructor(status=0){super('Book source unavailable');this.status=status;}
}
export async function openSource(value){
    const url=new URL(value,self.location.href);
    if(url.origin!==self.location.origin||url.username||url.password)throw new BookSourceError();
    url.searchParams.set('source','1');
    let size=null,whole=null;
    const cache=new Map();
    async function fetchRange(start,end,first=false,signal=null){
        const controller=new AbortController();
        const abort=()=>controller.abort();
        signal?.addEventListener('abort',abort,{once:true});
        const timer=setTimeout(abort,45000);
        try{
            if(signal?.aborted)throw new BookSourceError();
            const response=await fetch(url,{headers:{Range:'bytes='+start+'-'+end},
                cache:'no-store',credentials:'same-origin',redirect:'error',signal:controller.signal});
            if(response.status!==206&&!(first&&response.status===200)){
                await response.body?.cancel();
                throw new BookSourceError(response.status);
            }
            const lengthText=response.headers.get('Content-Length');
            const length=lengthText===null?null:Number(lengthText);
            if(length!==null&&(!Number.isSafeInteger(length)||length<1||length>MAX_SOURCE))
                throw new BookSourceError();
            if(response.status===200){
                // A reverse proxy may ignore Range. Keep compatibility without
                // retrying privately cached data or fetching the book twice.
                if(response.headers.has('Content-Range'))throw new BookSourceError();
                const reader=response.body?.getReader();
                if(!reader)throw new BookSourceError();
                let received=0;
                const pieces=[];
                for(;;){
                    const {value,done}=await reader.read();
                    if(done)break;
                    received+=value.byteLength;
                    if(received>MAX_SOURCE){await reader.cancel();throw new BookSourceError();}
                    pieces.push(value);
                }
                if(received<96||(length!==null&&received!==length))throw new BookSourceError();
                whole=new Blob(pieces);size=received;return;
            }
            const match=/^bytes (\d{1,10})-(\d{1,10})\/(\d{1,10})$/.exec(response.headers.get('Content-Range')??'');
            if(!match)throw new BookSourceError();
            const [from,to,total]=match.slice(1).map(Number);
            const count=to-from+1;
            if(total<96||total>MAX_SOURCE||from!==start||to!==Math.min(end,total-1)||
                count<1||(size!==null&&total!==size)||(length!==null&&length!==count))
                throw new BookSourceError();
            const reader=response.body?.getReader();
            if(!reader)throw new BookSourceError();
            const data=new Uint8Array(count);
            let offset=0;
            for(;;){
                const {value,done}=await reader.read();
                if(done)break;
                if(offset+value.byteLength>count){await reader.cancel();throw new BookSourceError();}
                data.set(value,offset);offset+=value.byteLength;
            }
            if(offset!==count)throw new BookSourceError();
            size=total;
            for(let n=0;n<count;n+=BLOCK){
                cache.set((start+n)/BLOCK,data.slice(n,n+BLOCK));
                if(cache.size>BLOCKS)cache.delete(cache.keys().next().value);
            }
            return data.subarray(0,BLOCK);
        }catch(error){
            controller.abort();
            throw error instanceof BookSourceError?error:new BookSourceError();
        }finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
    }
    await fetchRange(0,BLOCK-1,true);
    if(whole)return whole;
    return {size,slice(start,end=size){
        if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||end<start||end>size)
            throw new RangeError('Out of bounds book record');
        return {async arrayBuffer(signal){
            const out=new Uint8Array(end-start);
            for(let cursor=start;cursor<end;){
                const index=Math.floor(cursor/BLOCK);
                if(signal?.aborted)throw new BookSourceError();
                let bytes=cache.get(index);
                if(!bytes){
                    let last=index;
                    while(last<Math.floor((end-1)/BLOCK)&&last-index<BATCH-1&&!cache.has(last+1))last++;
                    bytes=await fetchRange(index*BLOCK,(last+1)*BLOCK-1,false,signal);
                }
                cache.delete(index);cache.set(index,bytes);
                const offset=cursor%BLOCK;
                const n=Math.min(bytes.length-offset,end-cursor);
                out.set(bytes.subarray(offset,offset+n),cursor-start);cursor+=n;
            }
            return out.buffer;
        }};
    }};
}
