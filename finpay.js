import axios from 'axios';
import crypto from 'crypto';
import { z } from 'zod';

const paymentRequestSchema = z.object({
    customer: z.object({
        email: z.string().email(),
        firstName: z.string().min(1),
        lastName: z.string().min(1),
        mobilePhone: z.string().min(6)
    }),
    order: z.object({
        amount: z.coerce.number().positive(),
        description: z.string().min(1)
    }),
    url: z.object({
        callbackUrl: z.string().url()
    }),
    sourceOfFunds: z.object({
        type: z.enum(['cc']),
        accountId: z.string().min(1).optional(),
        paymentCode: z.string().min(1).optional()
    }).optional(),
    card: z.object({
        storedOnFile: z.string().min(1),
        token: z.string().min(1).optional(),
        number: z.string().regex(/^\d{12,19}$/, 'Card number must be 12-19 digits'),
        expiryDate: z.string().regex(/^\d{4}$/, 'Expiry date must be YYMM'),
        cvv: z.string().regex(/^\d{3,4}$/, 'CVV must be 3-4 digits'),
        nameOnCard: z.string().min(1)
    }).optional(),
    billing: z.object({
        address: z.object({
            city: z.string().min(1),
            company: z.string().min(1).optional(),
            country: z.string().length(3),
            postcodeZip: z.string().min(1),
            stateProvince: z.string().min(1).optional(),
            stateProvinceCode: z.string().min(1).optional(),
            street: z.string().min(1),
            street2: z.string().min(1).optional()
        })
    }).optional(),
    device: z.object({
        ani: z.string().min(1),
        aniCallType: z.string().min(1),
        browser: z.string().min(1),
        fingerprint: z.string().min(1),
        hostname: z.string().min(1),
        ipAddress: z.string().regex(
            /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
            'Invalid IPv4 address'
        ),
        mobilePhoneModel: z.string().min(1)
    }).optional(),
    meta: z.object({
        data: z.any()
    }).optional(),
    recurring: z.object({
        subscribe: z.enum(['Y', 'N']),
        productCode: z.string().min(1),
        type: z.string().min(1),
        id: z.string().min(1),
        amount: z.coerce.number().positive(),
        interval: z.coerce.number().int().positive(),
        intervalUnit: z.string().min(1),
        maxInterval: z.coerce.number().int().positive(),
        startDate: z.string().regex(/^\d{8}$/, 'Start date must be YYYYMMDD'),
        endDate: z.string().regex(/^\d{8}$/, 'End date must be YYYYMMDD'),
        retry: z.object({
            interval: z.coerce.number().int().positive(),
            intervalUnit: z.string().min(1),
            maxInterval: z.coerce.number().int().positive()
        }).optional()
    }).optional()
});

const callbackRequestSchema = z.object({
    merchant: z.object({
        id: z.string().min(1)
    }),
    customer: z.object({
        id: z.string().optional()
    }),
    order: z.object({
        id: z.string().min(1),
        reference: z.string().min(1),
        amount: z.coerce.number().positive(),
        currency: z.string().min(3).max(3)
    }),
    transaction: z.object({
        acquirerId: z.string().nullable()
    }),
    sourceOfFunds: z.object({
        type: z.string().min(1),
        paymentCode: z.string().optional()
    }),
    meta: z.object({
        data: z.any().nullable()
    }),
    result: z.object({
        payment: z.object({
            status: z.string().min(1),
            statusDesc: z.string().min(1),
            userDesc: z.string().min(1),
            datetime: z.string().min(1),
            reference: z.string().min(1),
            channel: z.string().min(1),
            amount: z.coerce.number().positive()
        })
    }),
    signature: z.string().min(1)
});

export class FinPay {
    constructor(clientId, clientSecret, baseUrl) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.baseUrl = baseUrl;
        this.accessToken = null;
    }

    /**
     * Verify FinPay callback signature
     * Based on FinPay docs: hash_hmac("sha512", json_encode($fields), $key)
     * where $fields excludes the "signature" parameter
     */
    verifyCallbackSignature(payload, headerSignature = null) {
        try {
            // Create a copy of payload without the signature field
            const fieldsForSignature = { ...payload };
            delete fieldsForSignature.signature;

            // Check merchant ID matches
            if (fieldsForSignature.merchant.id !== this.clientId) {
                console.error('❌ Merchant ID mismatch in callback');
                return { valid: false, error: 'Merchant ID mismatch' };
            }

            // Generate the expected signature using client secret as key
            const dataToSign = JSON.stringify(fieldsForSignature);
            console.log('🔐 Data to sign:', dataToSign);

            const expectedSignature = crypto
                .createHmac('sha512', this.clientSecret)
                .update(dataToSign)
                .digest('hex');

            console.log('🔑 Expected signature:', expectedSignature);
            console.log('📝 Received body signature:', payload.signature);
            if (headerSignature) {
                console.log('📝 Received header signature:', headerSignature.substring(0, 50) + '...');
            }

            // Verify against body signature
            const bodySignatureValid = payload.signature === expectedSignature;

            // Verify against header signature if provided
            let headerSignatureValid = true;
            if (headerSignature) {
                // Header signature might be base64 encoded, try both
                headerSignatureValid = headerSignature === expectedSignature ||
                                     Buffer.from(headerSignature, 'base64').toString('hex') === expectedSignature;
            }

            return {
                valid: bodySignatureValid,
                headerValid: headerSignatureValid,
                expectedSignature,
                receivedBodySignature: payload.signature,
                receivedHeaderSignature: headerSignature
            };

        } catch (error) {
            console.error('❌ Signature verification error:', error.message);
            return {
                valid: false,
                error: error.message
            };
        }
    }

    getAccessToken() {
        if (!this.accessToken) {
            this.accessToken = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
        }
        return this.accessToken;
    }

    generateOrderId() {
        const rand = Math.floor(100000 + Math.random() * 900000).toString();
        const txId = `TX${rand}`;
        const timestamp = Date.now().toString().slice(-6);
        return `${txId}-${timestamp}`;
      }

    async doPayment(req, res) {
        const parsed = paymentRequestSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({
                message: 'Invalid request body',
                errors: parsed.error.flatten()
            });
        }
        if (!parsed.data.order.id) {
            parsed.data.order.id = this.generateOrderId();
        }

        const config = {
            method: 'post',
            maxBodyLength: Infinity,
            url: this.baseUrl,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${this.getAccessToken()}`
            },
            data: JSON.stringify(parsed.data)
        };

        try {
            const response = await axios.request(config);
            return res.status(200).json(response.data);
        } catch (error) {
            return res.status(error.response?.status || 500).json({
                message: 'Payment request failed',
                error: error.response?.data || error.message
            });
        }
    }

    async doCallback(req, res) {
        console.log('=== FinPay Callback Received ===');
        console.log('Headers:', JSON.stringify(req.headers, null, 2));
        console.log('Body:', JSON.stringify(req.body, null, 2));

        const parsed = callbackRequestSchema.safeParse(req.body);
        if (!parsed.success) {
            console.log('❌ Invalid callback payload:', parsed.error.issues);
            return res.status(400).json({
                status: 'error',
                message: 'Invalid callback payload',
                errors: parsed.error.issues
            });
        }

        const callbackData = parsed.data;

        // Verify signature for security
        console.log('\n🔐 Verifying callback signature...');
        const headerSignature = req.headers['x-signature'];
        const signatureVerification = this.verifyCallbackSignature(callbackData, headerSignature);

        if (!signatureVerification.valid) {
            console.log('❌ Invalid signature - callback rejected for security');
            return res.status(401).json({
                status: 'error',
                message: 'Invalid signature',
                details: 'Callback signature verification failed'
            });
        }

        console.log('✅ Signature verification passed');

        // Extract important information
        const {
            order,
            result: { payment },
            sourceOfFunds
        } = callbackData;

        console.log('✅ Callback validation successful');
        console.log(`📝 Processing payment status: ${payment.status} for order: ${order.id}`);
        console.log(`💰 Amount: ${payment.amount} ${order.currency}`);
        console.log(`🏪 Payment method: ${sourceOfFunds.type}`);

        try {
            switch (payment.status) {
                case 'PAID':
                    console.log('✅ Payment successful - processing completion');
                    break;
                case 'FAILED':
                    console.log('❌ Payment failed - processing failure');
                    break;
                case 'PENDING':
                    console.log('⏳ Payment pending - waiting for completion');
                    break;
                default:
                    console.log(`ℹ️ Unknown payment status: ${payment.status}`);
            }

            return res.status(200).json({
                status: 'success',
                message: 'Callback processed successfully',
                data: {
                    orderId: order.id,
                    paymentStatus: payment.status,
                    amount: payment.amount,
                    reference: payment.reference,
                    processedAt: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('❌ Callback processing error:', error.message);
            return res.status(500).json({
                status: 'error',
                message: 'Callback processing failed',
                error: error.message
            });
        }
    }
}