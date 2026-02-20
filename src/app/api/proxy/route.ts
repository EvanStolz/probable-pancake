import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');
  const store = searchParams.get('store');

  if (!id || !store) {
    return NextResponse.json({ error: 'Missing id or store parameter' }, { status: 400 });
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
