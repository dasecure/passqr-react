import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { Card } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { Loader2, CheckCircle2, XCircle } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useUser } from "@/hooks/use-user";
import { useLocation } from "wouter";

async function generateQRCode() {
  const csrfToken = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN'))
    ?.split('=')[1];

  const response = await fetch("/api/qr/generate", {
    method: "POST",
    headers: {
      "X-CSRF-Token": csrfToken || '',
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return (await response.json()).token;
}

async function verifyQRCode(token: string) {
  const csrfToken = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN'))
    ?.split('=')[1];

  const response = await fetch("/api/qr/verify", {
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

export default function QRCodeLogin() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const { user } = useUser();
  const queryClient = useQueryClient();
  const [verificationStatus, setVerificationStatus] = useState<"pending" | "success" | "error" | "linking">("pending");

  const { data: token, isLoading: isGenerating, error: generateError } = useQuery({
    queryKey: ["qrCode"],
    queryFn: generateQRCode,
    retry: 1,
  });

  const verifyMutation = useMutation({
    mutationFn: (token: string) => verifyQRCode(token),
    onSuccess: (data) => {
      if (data.success) {
        setVerificationStatus("success");
        // Force refresh user data
        queryClient.invalidateQueries({ queryKey: ['user'] });
        toast({
          title: "Success",
          description: "QR code login successful",
        });
        // Add delay to allow state update
        setTimeout(() => setLocation("/"), 2000);
      }
    },
    onError: (error) => {
      if (error instanceof Error && error.message === "Token not yet linked") {
        setVerificationStatus("linking");
      } else {
        setVerificationStatus("error");
        toast({
          variant: "destructive",
          title: "Error",
          description: error instanceof Error ? error.message : "Failed to verify QR code",
        });
      }
    },
  });

  useEffect(() => {
    let intervalId: NodeJS.Timeout;

    if (token && !user) {
      intervalId = setInterval(() => {
        verifyMutation.mutate(token);
      }, 3000);
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [token, user, verifyMutation]);

  if (isGenerating) {
    return (
      <div className="flex justify-center items-center py-8">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  if (generateError) {
    return (
      <div className="space-y-4">
        <div className="flex justify-center items-center py-8 text-destructive">
          <XCircle className="h-8 w-8" />
        </div>
        <div className="text-center text-sm text-muted-foreground">
          Failed to generate QR code. Please try again.
        </div>
      </div>
    );
  }

  const qrValue = `${window.location.origin}/qr/link/${token}`;

  return (
    <div className="space-y-4">
      <div className="text-center text-sm text-muted-foreground">
        {verificationStatus === "success" 
          ? "Login successful! Redirecting..."
          : "Scan this QR code with your mobile device"}
      </div>
      <Card className={`p-6 flex justify-center items-center bg-white relative ${verificationStatus === "success" ? "opacity-50" : ""}`}>
        <QRCodeSVG value={qrValue} size={200} level="H" />
        {verificationStatus === "success" && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/50">
            <CheckCircle2 className="h-16 w-16 text-primary" />
          </div>
        )}
      </Card>
      <div className="text-center text-sm">
        {verificationStatus === "pending" && 
          <span className="text-muted-foreground">Keep this page open while scanning</span>
        }
        {verificationStatus === "linking" && 
          <span className="text-green-600">Waiting for mobile device to complete login...</span>
        }
        {verificationStatus === "error" && 
          <span className="text-destructive">Failed to verify QR code. Please try again.</span>
        }
        {verificationStatus === "success" && 
          <span className="text-primary">Login successful! Redirecting...</span>
        }
      </div>
    </div>
  );
}
