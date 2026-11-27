// Only the worker fetches and parses the authorized binary book source.
export async function openReader(cfg){
    let worker=null,opening=null,sequence=0,urls=[],observer=null,generation=0;
    const pending=new Map();
    function stop(){
        worker?.terminate();worker=null;opening=null;
        for(const item of pending.values()){
            clearTimeout(item.timer);item.reject(new Error(cfg.failed));
        }
        pending.clear();
    }
    function call(action,value,onPreview){
        return new Promise((resolve,reject)=>{
            const id=++sequence;
            const timer=setTimeout(()=>{
                if(action!=='image'){stop();return;}
                pending.delete(id);reject(new Error(cfg.failed));
            },action==='image'?60000:180000);
            pending.set(id,{resolve,reject,timer,onPreview});
            worker.postMessage({id,action,value});
        });
    }
    async function ensure(){
        if(!opening){
            const path=new URL('./worker.js',import.meta.url);
            path.search=new URL(import.meta.url).search;
            worker=new Worker(path,{type:'module'});
            worker.addEventListener('error',stop);
            worker.onmessage=({data})=>{
                const item=pending.get(data.id);
                if(!item)return;
                if(data.preview!==undefined){item.onPreview?.(data.preview);return;}
                clearTimeout(item.timer);pending.delete(data.id);
                if(data.ok)item.resolve(data.value);
                else {
                    const message=data.status===401?cfg.signedOut:data.status===403?cfg.denied
                        :data.status===409?cfg.changed:data.status!==null?cfg.failed:cfg.unsupported;
                    item.reject(new Error(message||cfg.failed));
                }
            };
            opening=call('open',new URL(cfg.url,location.href).href)
                .catch(error=>{stop();throw error;});
        }
        return opening;
    }
    function cleanup(){
        generation++;observer?.disconnect();observer=null;
        for(const url of urls)URL.revokeObjectURL(url);urls=[];
    }
    function mount(container,html,imageToken){
        cleanup();
        const template=document.createElement('template');
        template.innerHTML=html;
        container.replaceChildren(template.content);
        if(!imageToken)return;
        const current=generation;
        const loads=new Map(),queue=[];
        let working=false;
        const pump=async()=>{
            if(working||current!==generation||!queue.length)return;
            working=true;
            const image=queue.shift();
            const key=Number(image.dataset.mobiImage);
            try{
                let src=loads.get(key);
                if(src===undefined){
                    const asset=await call('image',{token:imageToken,key});
                    if(current!==generation)return;
                    src=asset?URL.createObjectURL(new Blob([asset.bytes],{type:asset.mime})):null;
                    if(src)urls.push(src);
                    loads.set(key,src);
                }
                if(src){image.src=src;image.removeAttribute('data-mobi-image');}
                else image.remove();
            }catch{if(current===generation)image.remove();}
            finally{working=false;void pump();}
        };
        const found=container.querySelectorAll('img[data-mobi-image]');
        // Reserve only the natural alt-text line until the image's actual size
        // is known, and request at most one visible image at a time.
        function queueImage(image){queue.push(image);void pump();}
        if(typeof IntersectionObserver==='function'){
            observer=new IntersectionObserver(entries=>{
                for(const entry of entries)if(entry.isIntersecting){
                    observer?.unobserve(entry.target);queueImage(entry.target);
                }
            },{rootMargin:'160px'});
            for(const image of found)observer.observe(image);
        }else for(const image of found)queueImage(image);
    }
    addEventListener('pagehide',event=>{if(!event.persisted){stop();cleanup();}});
    return {async read(query,preview){
        await ensure();
        if(query.toc)return {toc:await call('toc')};
        if(query.locate)return {location:await call('locate',query.locate)};
        const data=await call('part',{part:query.part,fragment:query.fragment??'',preview:preview?.mode==='partial'},
            preview?html=>preview.paint({mount:container=>mount(container,html,false)}):null);
        return {count:data.count,hasNext:data.hasNext,mount:container=>mount(container,data.html,data.imageToken)};
    }};
}
