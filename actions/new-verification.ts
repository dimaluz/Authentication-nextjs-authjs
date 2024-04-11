'use server'

import { db } from "@/lib/db"
import { getUserByEmail } from "@/data/user"
import { getVerificationTokenByToken } from "@/data/verification-token"

export const newVerification = async (token: string) => {
    const existedToken = await getVerificationTokenByToken(token);

    if (!existedToken) {
        return {error: 'Token does not exist!'}
    }

    const expiredToken = new Date(existedToken.expires) < new Date();

    if (expiredToken) {
        return {error: 'Token has expired!'}
    }

    const existedUser = await getUserByEmail(existedToken.email)

    if (!existedUser) {
        return {error: 'Email does not exist!'}
    }

    await db.user.update({
        where: { id: existedUser.id},
        data: {
            emailVerified: new Date(),
            email: existedToken.email,
        }
    })

    await db.verificationToken.delete({
        where: { id: existedToken.id }
    })

    return {success: 'Email verified!'}
}