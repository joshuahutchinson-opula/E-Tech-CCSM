// ── MICROSOFT OAUTH TOKEN EXCHANGE ──────────────────────
// The browser can't call Microsoft's token endpoint directly (CORS).
// This endpoint proxies the exchange so the SPA gets tokens safely.
app.post('/api/auth/microsoft', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Authorization code required' });

    const clientId = process.env.MS_CLIENT_ID || 'e87a6592-aaa5-4a13-9c85-8dbc8e9cd7b2';
    const redirectUri = process.env.MS_REDIRECT_URI || 'https://e-tech-ccsm-production-19f0.up.railway.app';

    const tokenResponse = await fetch(
      `https://login.microsoftonline.com/${process.env.MS_TENANT_ID || '799ae988-9d3d-40d3-bf5c-93197f5d8d44'}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId,
          scope: 'https://graph.microsoft.com/Sites.Read.All Files.Read.All User.Read',
          code: code,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code'
        }).toString()
      }
    );

    const data = await tokenResponse.json();
    if (data.error) {
      console.error('Token exchange error:', data);
      return res.status(400).json({ error: data.error_description || data.error });
    }

    res.json(data);
  } catch (error) {
    console.error('Microsoft auth proxy error:', error);
    res.status(500).json({ error: 'Token exchange failed' });
  }
});

// ── SHAREPOINT INTEGRATION ──────────────────────────────
const SHAREPOINT_SITE = 'etechsystemsltd.sharepoint.com';
const SHAREPOINT_DRIVE_PATH = '/sites/Share/Shared%20Documents/E-Tech%20Maintenance';

async function fetchSharePointFiles(accessToken) {
  try {
    // Get the SharePoint site ID
    const siteResponse = await fetch(
      `https://graph.microsoft.com/v1.0/sites/${SHAREPOINT_SITE}:/sites/Share`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const siteData = await siteResponse.json();

    // Get the drive (document library)
    const driveResponse = await fetch(
      `https://graph.microsoft.com/v1.0/sites/${siteData.id}/drives`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const drives = await driveResponse.json();
    const documentsDrive = drives.value.find(d => d.name === 'Documents');

    // List files in E-Tech Maintenance folder
    const folderPath = '/E-Tech Maintenance';
    const childrenResponse = await fetch(
      `https://graph.microsoft.com/v1.0/drives/${documentsDrive.id}/root:${encodeURIComponent(folderPath)}:/children`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const folderData = await childrenResponse.json();

    // Recursively fetch all files from client subfolders
    const allFiles = [];
    for (const item of folderData.value) {
      if (item.folder) {
        // It's a client folder — get its contents
        const subResponse = await fetch(
          `https://graph.microsoft.com/v1.0/drives/${documentsDrive.id}/items/${item.id}/children`,
          { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        const subData = await subResponse.json();
        for (const file of subData.value) {
          if (!file.folder) {
            allFiles.push({
              name: file.name,
              type: getFileType(file.name),
              size: formatFileSize(file.size),
              modified: new Date(file.lastModifiedDateTime).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
              downloadUrl: file['@microsoft.graph.downloadUrl'],
              client: item.name,
              status: 'synced'
            });
          }
        }
      } else {
        allFiles.push({
          name: item.name,
          type: getFileType(item.name),
          size: formatFileSize(item.size),
          modified: new Date(item.lastModifiedDateTime).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          downloadUrl: item['@microsoft.graph.downloadUrl'],
          client: 'Root',
          status: 'synced'
        });
      }
    }

    return allFiles;
  } catch (error) {
    console.error('SharePoint fetch error:', error);
    return null;
  }
}

async function parseExcelToDevices(accessToken, fileUrl, deviceType) {
  try {
    // Download file content
    const fileResponse = await fetch(fileUrl, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!fileResponse.ok) return [];

    const contentType = fileResponse.headers.get('content-type') || '';

    if (contentType.includes('csv') || fileUrl.endsWith('.csv')) {
      const text = await fileResponse.text();
      return parseCSV(text, deviceType);
    }

    if (contentType.includes('spreadsheet') || fileUrl.endsWith('.xlsx') || fileUrl.endsWith('.xls')) {
      // For Excel files, return the raw text for now
      // Full Excel parsing would require a library like xlsx on the server
      // This gives us the structure; we'll enhance with proper parsing later
      return [];
    }

    return [];
  } catch (error) {
    console.error('File parse error:', error);
    return [];
  }
}

function parseCSV(text, deviceType) {
  const lines = text.split('\n').filter(line => line.trim());
  if (lines.length < 2) return [];

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g, ''));
  const devices = [];

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
    const device = {};

    headers.forEach((header, idx) => {
      device[header] = values[idx] || '';
    });

    // Map to our schema based on device type
    if (deviceType === 'camera') {
      devices.push({
        name: device.name || device.camera || device.camera_name || '',
        zone: device.zone || device.location || '',
        status: device.status || 'Unknown',
        ip_address: device.ip || device.ip_address || '',
        model: device.model || '',
        resolution: device.resolution || '',
        comments: device.comments || device.notes || ''
      });
    } else if (deviceType === 'door') {
      devices.push({
        name: device.name || device.door || '',
        site: device.site || device.location || '',
        client: device.client || '',
        reader: device.reader || '',
        lock_type: device.lock || device.lock_type || '',
        powered: device.powered || 'Yes',
        status: device.status || 'Offline',
        tech: device.tech || device.technician || '',
        ip_address: device.ip || device.ip_address || '',
        controller: device.controller || ''
      });
    } else if (deviceType === 'server') {
      devices.push({
        location: device.location || device.site || '',
        serial: device.serial || '',
        capacity: device.capacity || device.storage || '',
        used: device.used || device.used_storage || '',
        health: device.health || 'Good',
        apps: device.apps || device.applications || '',
        status: device.status || 'ONLINE'
      });
    } else if (deviceType === 'switch') {
      devices.push({
        name: device.name || device.switch || '',
        location: device.location || device.site || '',
        model: device.model || '',
        ip_address: device.ip || device.ip_address || '',
        firmware: device.firmware || '',
        username: device.username || '',
        password: device.password || '',
        mac: device.mac || device.mac_address || ''
      });
    }
  }

  return devices;
}

function getFileType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const types = { csv: 'csv', xlsx: 'xlsx', xls: 'xlsx', docx: 'docx', doc: 'docx', pdf: 'pdf', txt: 'txt', jpg: 'image', jpeg: 'image', png: 'image' };
  return types[ext] || 'file';
}

function formatFileSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

// ── SHAREPOINT SYNC ENDPOINT ────────────────────────────
app.get('/api/sharepoint/sync', authenticate, async (req, res) => {
  try {
    // Use the Microsoft Graph token from the auth header
    const authHeader = req.headers.authorization;
    const graphToken = authHeader ? authHeader.split(' ')[1] : null;

    if (!graphToken) {
      return res.status(401).json({ error: 'Microsoft Graph token required for SharePoint sync' });
    }

    const files = await fetchSharePointFiles(graphToken);

    if (!files) {
      return res.status(500).json({ error: 'Failed to fetch SharePoint files' });
    }

    res.json({ data: files, count: files.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── SHAREPOINT FILE PREVIEW ─────────────────────────────
app.get('/api/sharepoint/file', authenticate, async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'File URL required' });

    const authHeader = req.headers.authorization;
    const graphToken = authHeader ? authHeader.split(' ')[1] : null;

    const fileResponse = await fetch(url, {
      headers: { Authorization: `Bearer ${graphToken}` }
    });

    const contentType = fileResponse.headers.get('content-type') || '';
    const text = await fileResponse.text();

    res.json({ data: text, contentType });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
