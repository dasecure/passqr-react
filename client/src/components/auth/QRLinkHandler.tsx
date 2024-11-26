import { useEffect } from "react";
import { useParams, useLocation } from "wouter";
import { useUser } from "@/hooks/use-user";
import { useToast } from "@/hooks/use-toast";
import { Loader2 } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";

async function linkQRCode(token: string) {
  const csrfToken = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN'))
    ?.split('=')[1];

  const response = await fetch("/api/qr/link", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken || '',
    },
    credentials: "include",
    body: JSON.stringify({ token }),
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return response.json();
}

export default function QRLinkHandler() {
  const { token } = useParams<{ token: string }>();
  const [, setLocation] = useLocation();
  const { user } = useUser();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Add early return if token is undefined
  if (!token) {
    return null;
  }

  useEffect(() => {
    if (!user) {
      toast({
        variant: "destructive",
        title: "Authentication Required",
        description: "Please log in to link your QR code.",
      });
      setLocation(`/auth?returnTo=/qr/link/${token}`);
      return;
    }

    const handleLink = async () => {
      try {
        await linkQRCode(token);
        toast({
          title: "Success",
          description: "QR code linked successfully. You can now close this page.",
        });
        // Force refresh user data on mobile device
        queryClient.invalidateQueries({ queryKey: ['user'] });
      } catch (error) {
        toast({
          variant: "destructive",
          title: "Error",
          description: error instanceof Error ? error.message : "Failed to link QR code",
        });
        setLocation("/");
      }
    };

    handleLink();
  }, [token, user, setLocation, toast, queryClient]);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <Loader2 className="h-8 w-8 animate-spin" />
    </div>
  );
}
