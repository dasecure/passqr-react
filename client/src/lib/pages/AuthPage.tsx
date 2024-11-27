import { useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import LoginForm from "../components/auth/LoginForm";
import QRCodeLogin from "../components/auth/QRCodeLogin";
import PasswordResetForm from "../components/auth/PasswordResetForm";
import { motion } from "framer-motion";
import { useToast } from "@/hooks/use-toast";

export default function AuthPage() {
  const { toast } = useToast();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    
    if (error) {
      const errorMessages: Record<string, string> = {
        'oauth_error': 'An error occurred during Google sign in',
        'oauth_failed': 'Google sign in failed',
        'login_error': 'Unable to complete login'
      };
      
      toast({
        variant: "destructive",
        title: "Authentication Error",
        description: errorMessages[error] || 'An error occurred'
      });
    }
  }, [toast]);

  return (
    <div className="container flex items-center justify-center min-h-screen py-8">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="w-full max-w-md"
      >
        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold text-center">Welcome back</CardTitle>
            <CardDescription className="text-center">
              Choose your preferred login method
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="password" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="password">Password</TabsTrigger>
                <TabsTrigger value="reset">Reset</TabsTrigger>
                <TabsTrigger value="qr">QR Code</TabsTrigger>
              </TabsList>
              <TabsContent value="password">
                <LoginForm />
              </TabsContent>
              <TabsContent value="reset">
                <PasswordResetForm />
              </TabsContent>
              <TabsContent value="qr">
                <QRCodeLogin />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
