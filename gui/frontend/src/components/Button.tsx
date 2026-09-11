import type { ButtonHTMLAttributes } from "react";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "danger" | "ghost";
}

export default function Button({ variant = "ghost", className = "", ...rest }: Props) {
  const cls =
    variant === "primary" ? "btn-primary" : variant === "danger" ? "btn-danger" : "btn-ghost";
  return <button className={`${cls} ${className}`} {...rest} />;
}
