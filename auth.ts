import NextAuth from "next-auth"
import { JWT } from "next-auth/jwt"

import { PrismaAdapter } from '@auth/prisma-adapter'
import { db } from "./lib/db"
import authConfig from "@/auth.config"


import { getUserById } from "./data/user"
import { getTwoFactorConfirmationByUserId } from "./data/two-factor-confirmation"

declare module "next-auth" {
  interface Session {
    user: {
      id: string,
      role: "ADMIN" | "USER"
    }
  }
}

declare module "next-auth/jwt" {
  /** Returned by the `jwt` callback and `auth`, when using JWT sessions */
  interface JWT {
    role?: "ADMIN" | "USER"
  }
}

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth({
  pages:{
    signIn: "/auth/login",
    error: "/auth/error",
  },

  events: {
    async linkAccount({user}){
      await db.user.update({
        where: { id: user.id },
        data: { emailVerified: new Date()}
      })
    }
  },
  callbacks: {
    async signIn({ user, account }) {
      
      // Allow OAuth without email verification
      if (account?.provider !== 'credentials') return true;

      const existedUser = await getUserById(user.id);

      // Prevent sign in without email verification
      if (!existedUser?.emailVerified) return false;

      if (existedUser.isTwoFactorEnable) {
        const twoFactorConfirmation = await getTwoFactorConfirmationByUserId(existedUser.id)

        if (!twoFactorConfirmation) return false

        // Delete 2FA confirmation for next sign in
        await db.twoFactorConfirmation.delete({
          where: {id: twoFactorConfirmation.id}
        })
      }

      return true;
    },

    async session({ token, session }){
      
      if (token.sub && session.user) {
        session.user.id = token.sub
      }

      if (token.role && session.user) {
        session.user.role = token.role;
      }

      if (session.user) {
        session.user.isTwoFactorEnabled = token.isTwoFactorEnabled as boolean;
      }

      return session;
    },

    async jwt({ token }){
      
      if(!token.sub) return token;

      const existedUser = await getUserById(token.sub);

      if (!existedUser) return token;

      token.role = existedUser.role;
      token.isTwoFactorEnabled = existedUser.isTwoFactorEnable
      return token;
    }
  },
  adapter: PrismaAdapter(db),
  session: { strategy: "jwt"},
  ...authConfig,
})