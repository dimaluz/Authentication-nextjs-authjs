'use server'

import * as z from 'zod'

import { ResetSchema } from "@/schemas"
import { getUserByEmail } from "@/data/user"
import { sendPasswordResetEmail } from '@/lib/mail'
import { generatePasswordResetToken } from '@/lib/tokens'

export const reset = async (values: z.infer<typeof ResetSchema>) => {
    const validateFields = ResetSchema.safeParse(values)

    if (!validateFields.success) {
        return {error: 'Invalid Email!'}
    }

    const { email } = validateFields.data

    const existedUser = await getUserByEmail(email)

    if (!existedUser) {
        return {error: 'Email not found!'}
    }

    //Generate token and send email

    const passwordResetToken = await generatePasswordResetToken(email)
    await sendPasswordResetEmail(
        passwordResetToken.email,
        passwordResetToken.token,
    )

    return {success: 'Reset email sent!'}
    
}