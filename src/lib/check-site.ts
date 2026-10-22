import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const Input = z.object({
  url: z.string().trim().min(3).max(300),
});

export const checkSite = createServerFn({ method: "POST" })
  .validator(Input)
  .handler(async ({ data }) => {
    const { runCheck } = await import("./check-site.server");
    return runCheck(data.url);
  });
