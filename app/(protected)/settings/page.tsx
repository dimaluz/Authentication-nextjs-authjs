'use client'

import { signOut } from "next-auth/react"

import { Button } from "@/components/ui/button"
import { useCurrentUser } from "@/hooks/use-current-user"


const SettingsPage = () => {

    const user = useCurrentUser()

    const onClick = () => {
        signOut()
    }

    return (
        <div className='bg-white p-10 rounded-xl'>
            
            <Button 
                type="submit"
                onClick={onClick}
            >
                Sign out
            </Button>
        </div>
    )
}

export default SettingsPage