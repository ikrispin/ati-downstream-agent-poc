const sharp=require(process.argv[2]);
const paths=JSON.parse(process.argv[3]);
(async()=>{for(const p of paths){await sharp(p,{density:240}).resize({width:2700}).png().toFile(p.replace(/\.svg$/,'.png'));}})().catch(e=>{console.error(e.message);process.exit(1)});
