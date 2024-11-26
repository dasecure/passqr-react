import { Button } from "@/components/ui/button";
import { useUser } from "../hooks/use-user";
import { Loader2 } from "lucide-react";
import type { User } from "@db/schema";
import { useLocation } from "wouter";

export default function HomePage() {
  const { user, logout, isLoading } = useUser();
  const [, setLocation] = useLocation();

  const handleLogout = async () => {
    try {
      await logout();
      setLocation("/auth");
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-md mx-auto">
        <h1 className="text-2xl font-bold mb-4">Welcome, {user?.username}!</h1>
        <Button onClick={handleLogout} variant="outline" className="w-full">
          Logout
        </Button>
      </div>
    </div>
  );
}
