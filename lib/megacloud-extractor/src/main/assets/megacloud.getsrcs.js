"use strict";
// solution inspired from https://github.com/drblgn/rabbit_wasm/blob/main/rabbit.ts
// solution inspired from https://github.com/shimizudev/consumet.ts/blob/master/dist/extractors/megacloud/megacloud.getsrcs.js

const baseUrl = 'https://megacloud.tv';
const userAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

async function getMegaCloudKey() {
    const resp = await fetch('https://raw.githubusercontent.com/yogesh-hacker/MegacloudKeys/refs/heads/main/keys.json');
    const data = await resp.json();
    return data?.mega;
}

async function getSources(xrax) {
    try {
        const res = await fetch(`${baseUrl}/embed-2/v2/e-1/getSources?id=${xrax}`, {
            headers: {
                'User-Agent': userAgent,
                'Referer': baseUrl,
                'Origin': baseUrl
            }
        });

        const data = await res.json();
        if (!data.sources) {
            console.error("No sources found");
            return;
        }

        const keyHex = await getMegaCloudKey();
        const decryptedJson = decryptSources(hexToBytes(keyHex), data.sources);

        return {
            sources: [
                JSON.parse(decryptedJson).map(source => {
                    return {
                        file: source.file,
                    }
                })
            ],
            tracks: data.tracks,
        };
    } catch (e) {
        console.error(e)
    }
}
