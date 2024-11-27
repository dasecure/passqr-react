import { Button } from "@/components/ui/button";
import { useUser } from "@/hooks/use-user";
import { Loader2 } from "lucide-react";
import type { User } from "@db/schema";
import { useLocation } from "wouter";

export default function HomePage() {
  const { user, logout } = useUser();
  const [, setLocation] = useLocation();

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  const handleLogout = async () => {
    await logout();
    setLocation("/auth");
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-2xl font-bold">Welcome, {user.username}!</h1>
        <Button variant="outline" onClick={handleLogout}>
          Logout
        </Button>
      </div>
      
      <div className="space-y-4">
        <div className="p-4 bg-card rounded-lg border">
          <h2 className="text-lg font-semibold mb-2">User Information</h2>
          <div className="space-y-2">
            <p><span className="font-medium">Email:</span> {user.email}</p>
            <p><span className="font-medium">Login Provider:</span> {user.provider}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
