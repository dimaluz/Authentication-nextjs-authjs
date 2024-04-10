import NextAuth from "next-auth"
import { JWT } from "next-auth/jwt"

import { PrismaAdapter } from '@auth/prisma-adapter'
import { db } from "./lib/db"
import authConfig from "@/auth.config"


import { getUserById } from "./data/user"

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
    // async signIn({ user }) {

    //   const existedUser = await getUserById(user.id);

    //   if (!existedUser || !existedUser.emailVarified) {
    //     return false;
    //   }

    //   return true;
    // },

    async session({ token, session }){
      
      if (token.sub && session.user) {
        session.user.id = token.sub
      }

      if (token.role && session.user) {
        session.user.role = token.role;
      }

      return session;
    },

    async jwt({ token }){
      
      if(!token.sub) return token;

      const existedUser = await getUserById(token.sub);

      if (!existedUser) return token;

      token.role = existedUser.role;
      return token;
    }
  },
  adapter: PrismaAdapter(db),
  session: { strategy: "jwt"},
  ...authConfig,
})