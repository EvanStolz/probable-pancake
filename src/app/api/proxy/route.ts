import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');
  const store = searchParams.get('store');
  const metadataOnly = searchParams.get('metadata') === 'true';

  if (!id || !store) {
    return NextResponse.json({ error: 'Missing id or store parameter' }, { status: 400 });
  }

  if (metadataOnly) {
    try {
      const metadata = await fetchStoreMetadata(id, store);
      return NextResponse.json(metadata);
    } catch (error) {
      console.error('Metadata fetch error:', error);
      return NextResponse.json({ error: 'Failed to fetch metadata' }, { status: 500 });
    }
  }

  let downloadUrl = '';
  if (store === 'chrome') {
    downloadUrl = `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=114.0&acceptformat=crx2,crx3&x=id%3D${id}%26installsource%3Dondemand%26uc`;
  } else if (store === 'edge') {
    downloadUrl = `https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&prod=edgecrx&x=id%3D${id}%26installsource%3Dondemand%26uc`;
  } else {
    return NextResponse.json({ error: 'Invalid store' }, { status: 400 });
  }

  try {
    const response = await fetch(downloadUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch from store: ${response.statusText}`);
    }

    const blob = await response.blob();
    const buffer = await blob.arrayBuffer();

    return new NextResponse(buffer, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${id}.crx"`,
      },
    });
  } catch (error) {
    console.error('Proxy error:', error);
    return NextResponse.json({ error: 'Failed to download extension' }, { status: 500 });
  }
}

async function fetchStoreMetadata(id: string, store: string) {
  const url = store === 'chrome'
    ? `https://chromewebstore.google.com/detail/${id}`
    : `https://microsoftedge.microsoft.com/addons/detail/${id}`;

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });

    if (!response.ok) return null;
    const html = await response.text();

    const metadata = {
      publisher: '',
      rating: 0,
      ratingCount: 0,
      userCount: '0',
      lastUpdated: '',
    };

    if (store === 'chrome') {
      // Chrome Web Store (Modern)
      const ratingMatch = html.match(/aria-label="Rated ([0-9.]+) out of 5 stars/);
      if (ratingMatch) metadata.rating = parseFloat(ratingMatch[1]);

      const ratingCountMatch = html.match(/([0-9,.]+) ratings/);
      if (ratingCountMatch) metadata.ratingCount = parseInt(ratingCountMatch[1].replace(/,/g, ''));

      const userCountMatch = html.match(/([0-9,.]+)\+? users/);
      if (userCountMatch) metadata.userCount = userCountMatch[1] + '+';

      const dateMatch = html.match(/Updated ([A-Za-z]+ [0-9]+, [0-9]{4})/);
      if (dateMatch) metadata.lastUpdated = dateMatch[1];

      const pubMatch = html.match(/itemprop="author".*?><span.*?>(.*?)<\/span>/s) || html.match(/by (.*?)<\/div>/);
      if (pubMatch) metadata.publisher = pubMatch[1].trim().replace(/<[^>]*>?/gm, '');
    } else {
      // Edge Addons
      const ratingMatch = html.match(/aria-label="Average rating ([0-9.]+) out of 5 stars/);
      if (ratingMatch) metadata.rating = parseFloat(ratingMatch[1]);

      const ratingCountMatch = html.match(/([0-9,.]+) users rated/);
      if (ratingCountMatch) metadata.ratingCount = parseInt(ratingCountMatch[1].replace(/,/g, ''));

      const userCountMatch = html.match(/([0-9,.]+)\+? users/);
      if (userCountMatch) metadata.userCount = userCountMatch[1] + '+';

      const dateMatch = html.match(/Updated: ([A-Za-z]+ [0-9]+, [0-9]{4})/) || html.match(/Last updated: (.*?)</);
      if (dateMatch) metadata.lastUpdated = dateMatch[1];

      const pubMatch = html.match(/itemprop="author".*?>(.*?)<\/div>/s) || html.match(/By (.*?)<\/div>/);
      if (pubMatch) metadata.publisher = pubMatch[1].trim().replace(/<[^>]*>?/gm, '');
    }

    return metadata;
  } catch (e) {
    console.error('Scraping error:', e);
    return null;
  }
}
