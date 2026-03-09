import { NextResponse } from 'next/server';
import { generateServiceIdentity } from '@shared/security-utils/service-identity';
import { forwardToGateway } from '@/services/gateway-adapter/gateway';

import crypto from 'crypto';

/**
 * GitHub Webhook Receiver
 * Allows for automated security audits on push events.
 */
export async function POST(req: Request) {
    try {
        const rawBody = await req.text();
        const payload = JSON.parse(rawBody);

        // 1. Verify Webhook Signature
        const signature = req.headers.get('x-hub-signature-256');
        const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;

        // Only enforce if secret is configured (fail-open or fail-closed based on env, here we fail-closed if signature is present but secret is missing, or require it)
        if (webhookSecret) {
            if (!signature) {
                return NextResponse.json({ error: 'Missing X-Hub-Signature-256 header' }, { status: 401 });
            }

            const expectedSignature = `sha256=${crypto.createHmac('sha256', webhookSecret).update(rawBody).digest('hex')}`;

            // Expected signature check using timingSafeEqual to prevent timing attacks
            const sigBuffer = Buffer.from(signature);
            const expectedBuffer = Buffer.from(expectedSignature);

            if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
                return NextResponse.json({ error: 'Invalid webhook signature' }, { status: 401 });
            }
        }

        // 2. Identify if it's a push event
        const event = req.headers.get('x-github-event');
        if (event !== 'push') {
            return NextResponse.json({ message: 'Event ignored' }, { status: 200 });
        }

        const repoFullName = payload?.repository?.full_name;
        if (!repoFullName) {
            return NextResponse.json({ error: 'Invalid payload: Repository not found' }, { status: 400 });
        }

        // 3. Identify the user (In PoC, we map to a specific system user or use an installation ID)
        // For now, we'll assume a system-wide audit or use the repo owner if mapped.
        // We shouldn't use a fake UUID if it conflicts with actual FK constraints, 
        // passing undefined logic handles system jobs.
        const systemUserId = undefined;

        console.log(`[GitHub Webhook] Received push for ${repoFullName}. Triggering automated audit...`);

        // 4. Trigger Audit via Gateway
        const identity = generateServiceIdentity('api-route');
        const jobId = await forwardToGateway(repoFullName, 'repo', identity, systemUserId);

        return NextResponse.json({
            message: 'Automated audit triggered',
            jobId
        }, { status: 202 });

    } catch (error: any) {
        console.error('[GitHub Webhook Error]', error);
        return NextResponse.json({ error: error.message }, { status: 500 });
    }
}
