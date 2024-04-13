'use server'

import { getPasswordResetTokenByToken } from '@/data/password-reset-token'
import { getUserByEmail } from '@/data/user'
import { NewPasswordSchema } from '@/schemas'

import * as z from 'zod'
import bcrypt from 'bcryptjs'
import { db } from '@/lib/db'

export const newPassword = async (
    values: z.infer<typeof NewPasswordSchema>,
    token: string | null,
) => {
    if (!token) {
        return {error: 'Missing token!'}
    }

    const validatedFields = NewPasswordSchema.safeParse(values)
    if (!validatedFields.success) {
        return {error: "Invalid fields!"}
    }

    const { password } = validatedFields.data

    const existedToken = await getPasswordResetTokenByToken(token)

    if (!existedToken) {
        return {error: 'Invalid token!'}
    }

    const hasExpired = new Date(existedToken.expires) < new Date()

    if (hasExpired) {
        return {error: 'Token has expired!'}
    }

    const existedUser = await getUserByEmail(existedToken.email)

    if (!existedUser) {
        return {error: 'Email does not exist!'}
    }

    const hashedPassword = bcrypt.hash(password, 10)
    await db.user.update({
        where: {id: existedUser.id},
        data: {password: hashedPassword},
    })

    await db.passwordResetToken.delete({
        where: {id: existedToken.id},
    })

    return {success: 'Password updated!'}
}