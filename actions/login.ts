'use server';

import * as z from 'zod';
import { signIn } from '@/auth';
import { AuthError } from 'next-auth';
import { LoginSchema } from '@/schemas';
import { DEFAULT_LOGIN_REDIRECT } from '@/routes';
import { getUserByEmail } from '@/data/user';
import { generateVerificationToken } from '@/lib/tokens';

export const login = async (values: z.infer<typeof LoginSchema>) => {
    const validatedFields = LoginSchema.safeParse(values)

    if (!validatedFields.success){
        return { error: 'Invalid fields!' };
    }

    const { email, password } = validatedFields.data;

    const existedUser = await getUserByEmail(email)

    if (!existedUser || !existedUser.email || !existedUser.password) {
        return {error: 'Email does not exist!'}
    }

    if (!existedUser.emailVerified) {
        const verificationToken = await generateVerificationToken(existedUser.email)
        return {success: 'Confirmation email sent!'}
    }

    try{
        await signIn("credentials",{
            email,
            password,
            redirectTo: DEFAULT_LOGIN_REDIRECT,
        })
    }catch (error){
        if (error instanceof AuthError){
            switch (error.type) {
                case 'CredentialsSignin':
                    return {error: 'Invalid Credentials!'}
                default:
                    return {error: 'Something went wrong!'}
            }
        }
        throw error;
    }
}