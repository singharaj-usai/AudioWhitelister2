const axios = require('axios');
const config = require('./config.json');

const authCookie = config.cookie;
const universeId = config.universeId;
const groupId = config.groupId;

async function wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function main(cookie, universeId, groupId) {
    try {
        console.log('Verifying credentials...');
        await setCredentials(true, cookie);
        
        // Test authentication
        const testAuth = await getCurrentUser(cookie);
        console.log('Successfully authenticated as:', testAuth.name);
        
        // Verify group membership
        try {
            const groupCheck = await axios.get(`https://groups.roblox.com/v1/groups/${groupId}/roles`);
            console.log('Successfully verified group access');
        } catch (error) {
            console.error('Group access error:', error.message);
            return;
        }

        const audioList = await fetchAudios(cookie, groupId);
        console.log(`Detected ${audioList.length} audios. Whitelisting audios...`);

        await processQueue(cookie, universeId, audioList);
    } catch (error) {
        console.error('Error during the process:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response headers:', error.response.headers);
            console.error('Response data:', error.response.data);
        }
    }
}

async function getToken(cookie) {
    try {
        const response = await axios.post('https://auth.roblox.com/v2/logout', null, {
            headers: {
                'Cookie': `.ROBLOSECURITY=${cookie}`,
                'Accept': 'application/json',
                'User-Agent': 'Roblox/1.0',
                'Referer': 'https://www.roblox.com/'
            },
            validateStatus: (status) => status === 403
        });

        const token = response.headers['x-csrf-token'];
        
        if (!token) {
            throw new Error('No CSRF token in response headers');
        }

        return token;
    } catch (error) {
        if (error.response && error.response.headers['x-csrf-token']) {
            return error.response.headers['x-csrf-token'];
        }
        throw new Error(`Failed to get CSRF token: ${error.message}`);
    }
}

async function getCurrentUser(cookie) {
    try {
        const response = await axios.get('https://users.roblox.com/v1/users/authenticated', {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': `.ROBLOSECURITY=${cookie}`,
                'Accept': 'application/json'
            },
        });
        
        if (!response.data || !response.data.id) {
            throw new Error('Invalid authentication response');
        }
        
        return response.data;
    } catch (error) {
        if (error.response && error.response.status === 401) {
            throw new Error('Invalid or expired .ROBLOSECURITY cookie');
        }
        throw new Error(`Authentication failed: ${error.message}`);
    }
}

let csrfToken;
let currentUser;

async function setCredentials(isFirstRun, cookie) {
    try {
        if (!cookie || cookie.trim() === '') {
            throw new Error('Cookie is required');
        }

        // Enhanced cookie cleaning
        let cleanCookie = cookie.trim();
        // Remove quotes if present
        cleanCookie = cleanCookie.replace(/^["']|["']$/g, '');
        // Extract value if full cookie format is provided
        if (cleanCookie.includes('.ROBLOSECURITY=')) {
            cleanCookie = cleanCookie.split('.ROBLOSECURITY=')[1].split(';')[0];
        }

        // Get CSRF token first
        csrfToken = await getToken(cleanCookie);
        if (!csrfToken) {
            throw new Error('Failed to obtain CSRF token');
        }

        // Set default headers with additional security headers
        axios.defaults.headers.common = {
            'Cookie': `.ROBLOSECURITY=${cleanCookie}`,
            'X-CSRF-TOKEN': csrfToken,
            'Accept': 'application/json',
            'User-Agent': 'Roblox/1.0',
            'Origin': 'https://www.roblox.com',
            'Referer': 'https://www.roblox.com/'
        };

        if (isFirstRun) {
            // Verify authentication
            currentUser = await getCurrentUser(cleanCookie);
            console.log(`Logged in as ${currentUser.name} [${currentUser.id}]`);
        }

    } catch (error) {
        console.error('Authentication error:', error.message);
        throw error;
    }
}

async function fetchAudios(cookie, groupId) {
    let audioList = [];
    let cursor = null;

    while (true) {
        const response = await axios.get('https://itemconfiguration.roblox.com/v1/creations/get-assets', {
            params: {
                assetType: 'Audio',
                isArchived: 'false',
                groupId: groupId,
                limit: 100,
                cursor: cursor,
            },
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': csrfToken,
                'Cookie': `.ROBLOSECURITY=${cookie}`,
            },
        });

        if (response.status !== 200) throw new Error(`Failed to fetch audios: ${response.statusText}`);

        audioList = audioList.concat(response.data.data.map((audio) => ({ name: audio.name, id: audio.assetId })));

        if (!response.data.nextPageCursor) break;
        cursor = response.data.nextPageCursor;
    }

    return audioList;
}

async function whitelist(cookie, universeId, audioName, audioId, retries = 0, delayFactor = 1) {
    try {
        if (!csrfToken) {
            await setCredentials(false, cookie);
        }

        const data = {
            requests: [{ 
                subjectType: 'Universe', 
                subjectId: universeId, 
                action: 'Use'
            }]
        };

        const response = await axios.patch(
            `https://apis.roblox.com/asset-permissions-api/v1/assets/${audioId}/permissions`,
            data,
            {
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                    'Cookie': `.ROBLOSECURITY=${cookie}`,
                    'Accept': 'application/json',
                    'User-Agent': 'Roblox/1.0',
                    'Origin': 'https://www.roblox.com',
                    'Referer': 'https://www.roblox.com/',
                    'Access-Control-Allow-Origin': '*'
                },
            }
        );

        if (response.status !== 200) {
            throw new Error(`Failed to whitelist audio ${audioName}: ${response.statusText}`);
        }

        console.log(`Whitelisted audio: ${audioName}`);
    } catch (error) {
        if (error.response && error.response.status === 401) {
            if (retries < 3) {
                console.warn(`Authentication error for ${audioName}. Retrying... (Attempt ${retries + 1}/3)`);
                await wait(1000 * delayFactor);
                await setCredentials(true, cookie); // Full refresh of credentials
                return whitelist(cookie, universeId, audioName, audioId, retries + 1, delayFactor * 2);
            } else {
                console.error(`Failed to authenticate after 3 retries for audio ${audioName}`);
            }
        } else if (error.response && error.response.status === 429) {
            const retryAfter = error.response.headers['retry-after']
                ? parseInt(error.response.headers['retry-after']) * 1000
                : 1000 * delayFactor;

            if (retries < 10) {
                console.warn(
                    `Rate limit hit. Retrying audio ${audioName} in ${retryAfter / 1000} seconds (Attempt ${
                        retries + 1
                    }/10)...`
                );
                await wait(retryAfter);
                await whitelist(cookie, universeId, audioName, audioId, retries + 1, delayFactor * 2);
            } else {
                console.error(`Failed to whitelist audio ${audioName} after 10 retries due to rate limiting.`);
            }
        } else {
            console.error(`Error whitelisting audio ${audioName}: ${error.message}`);
        }
    }
}

async function processQueue(cookie, universeId, audioList) {
    const maxConcurrent = 50;
    const queue = [...audioList];
    
    while (queue.length > 0) {
        const batch = queue.splice(0, maxConcurrent);

        await Promise.all(
            batch.map((audio) => whitelist(cookie, universeId, audio.name, audio.id))
        );
    }

    console.log("All audios whitelisted successfully.");
}


main(authCookie, universeId, groupId);
