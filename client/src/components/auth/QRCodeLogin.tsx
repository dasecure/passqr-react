import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { Card } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { Loader2 } from "lucide-react";

export default function QRCodeLogin() {
  const [qrData, setQrData] = useState<string>("");
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    // In a real implementation, this would fetch a unique QR code from the server
    const generateQRCode = async () => {
      try {
        // Simulate API call delay
        await new Promise(resolve => setTimeout(resolve, 1000));
        const randomToken = Math.random().toString(36).substring(7);
        setQrData(`https://auth.example.com/qr/${randomToken}`);
        setIsLoading(false);
      } catch (error) {
        toast({
          variant: "destructive",
          title: "Error",
          description: "Failed to generate QR code",
        });
      }
    };

    generateQRCode();
  }, [toast]);

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-8">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="text-center text-sm text-muted-foreground">
        Scan this QR code with your authenticator app
      </div>
      <Card className="p-6 flex justify-center items-center bg-white">
        <QRCodeSVG value={qrData} size={200} level="H" />
      </Card>
      <div className="text-center text-sm text-muted-foreground">
        Keep this page open while scanning
      </div>
    </div>
  );
}
