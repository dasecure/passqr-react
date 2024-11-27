import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import LoginForm from "@/components/auth/LoginForm";
import QRCodeLogin from "@/components/auth/QRCodeLogin";
import PasswordResetForm from "@/components/auth/PasswordResetForm";
import { useToast } from "@/hooks/use-toast";
import { useEffect } from "react";
import { useLocation } from "wouter";
import { useUser } from "@/hooks/use-user";

export default function AuthPage() {
  const [tab, setTab] = useState<string>("login");
  const { toast } = useToast();
  const [location] = useLocation();
  const { user } = useUser();

  useEffect(() => {
    // Redirect if user is already logged in
    if (user) {
      window.location.href = '/';
      return;
    }

    // Check for error query parameter
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    const token = params.get('token');

    if (error) {
      toast({
        variant: "destructive",
        title: "Authentication Error",
        description: error === 'oauth_failed' 
          ? "Failed to authenticate with Google"
          : error === 'invalid_state'
          ? "Invalid authentication state"
          : "An error occurred during authentication",
      });
    }

    // If reset token is present, switch to reset tab
    if (token) {
      setTab("reset");
    }
  }, [location, toast, user]);

  return (
    <div className="container relative min-h-screen flex-col items-center justify-center grid lg:max-w-none lg:grid-cols-2 lg:px-0">
      <div className="relative hidden h-full flex-col bg-muted p-10 text-white lg:flex dark:border-r">
        <div className="absolute inset-0 bg-primary" />
        <div className="relative z-20 flex items-center text-lg font-medium">
          PassQR Authentication
        </div>
        <div className="relative z-20 mt-auto">
          <blockquote className="space-y-2">
            <p className="text-lg">
              Secure, Multi-factor Authentication System
            </p>
          </blockquote>
        </div>
      </div>
      <div className="p-4 lg:p-8 h-full flex items-center">
        <div className="mx-auto flex w-full flex-col justify-center space-y-6 sm:w-[350px]">
          <div className="flex flex-col space-y-2 text-center">
            <h1 className="text-2xl font-semibold tracking-tight">
              Welcome to PassQR
            </h1>
            <p className="text-sm text-muted-foreground">
              Choose your preferred authentication method
            </p>
          </div>
          <Tabs value={tab} onValueChange={setTab} className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="login">Login</TabsTrigger>
              <TabsTrigger value="qr">QR Code</TabsTrigger>
              <TabsTrigger value="reset">Reset</TabsTrigger>
            </TabsList>
            <TabsContent value="login" className="mt-4">
              <LoginForm />
            </TabsContent>
            <TabsContent value="qr" className="mt-4">
              <QRCodeLogin />
            </TabsContent>
            <TabsContent value="reset" className="mt-4">
              <PasswordResetForm />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}
