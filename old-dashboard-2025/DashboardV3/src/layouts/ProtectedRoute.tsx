import React, { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute = ({ children }: ProtectedRouteProps) => {
  const [isAuthorized, setIsAuthorized] = useState<boolean | null>(null);

  useEffect(() => {
    const Role = localStorage.getItem("status");
    console.log('Role from localStorage:', Role); // ← มองเห็นแล้ว
    
    if (Role === 'Authenticated') {
      setIsAuthorized(true);
    } else {
      alert('You are not authorized to access this page.');
      setIsAuthorized(false);
    }
  }, []);

  // ← รอจนกว่า state update แล้ว
  if (isAuthorized === null) {
    return <div>Loading...</div>;
  }

  if (!isAuthorized) {
    return <Navigate to="/home/login" replace />;
  }

  return children;
};

export default ProtectedRoute;