
import crypto from 'crypto'
import { v4 as uuidv4 } from 'uuid'

import { db } from './db'
import { getPasswordResetTokenByEmail } from '@/data/password-reset-token'
import { getVerificationTokenByEmail } from '@/data/verification-token'
import { getTwoFactorTokenByEmail } from '@/data/two-factor-token'


export const generateTwoFactorToken = async (email: string) => {
    const token = crypto.randomInt(100_000, 1_000_000).toString()
    const expires = new Date(new Date().getTime() + 3600 * 1000)

    const existedToken = await getTwoFactorTokenByEmail(email)

    if (existedToken) {
        await db.twoFactorToken.delete({
            where: {
                id: existedToken.id
            }
        })
    }
    const twoFactorToken = await db.twoFactorToken.create({
        data: {
            email,
            token,
            expires,
        }
    })

    return twoFactorToken
}


export const generatePasswordResetToken = async (email: string) => {
    const token = uuidv4()
    const expires = new Date(new Date().getTime() + 3600 * 1000)

    const existedToken = await getPasswordResetTokenByEmail(email)

    if (existedToken) {
        await db.passwordResetToken.delete({
            where: {id: existedToken.id}
        })
    }

    const passwordResetToken = await db.passwordResetToken.create({
        data: {
            email,
            token,
            expires,
        }
    })

    return passwordResetToken
}

export const generateVerificationToken = async (email: string) => {
    const token = uuidv4()
    const expires = new Date(new Date().getTime() + 3600 * 1000)

    const existedToken = await getVerificationTokenByEmail(email)

    if (existedToken) {
        await db.verificationToken.delete({
            where: {
                id: existedToken.id,
            },
        })
    }

    const verificationToken = await db.verificationToken.create({
        data: {
            email,
            token,
            expires,
        }
    })
    return verificationToken
}