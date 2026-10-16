// Global Ambient Declarations for Natural Investigate Canvas
declare module 'lucide-react';
declare module 'react-day-picker';
declare module 'vaul';
declare module 'tailwind-merge';
declare module '@radix-ui/*';
declare module '@lovable.dev/*';
declare module 'vitest';
declare module 'vitest/*';
declare module '@vitejs/*';
declare module '*.css';
declare module '*.css?url';
declare module '@testing-library/*';

declare module 'embla-carousel-react' {
  export type UseEmblaCarouselType = [any, any];
  export default function useEmblaCarousel(options?: any, plugins?: any): UseEmblaCarouselType;
}

declare module 'recharts' {
  export interface LegendProps {
    [key: string]: any;
  }
  export const ResponsiveContainer: any;
  export const AreaChart: any;
  export const Area: any;
  export const BarChart: any;
  export const Bar: any;
  export const LineChart: any;
  export const Line: any;
  export const XAxis: any;
  export const YAxis: any;
  export const Tooltip: any;
  export const Legend: any;
}

declare module 'react-hook-form' {
  export type FieldValues = Record<string, any>;
  export type FieldPath<T = any> = string;
  export type ControllerProps<TFieldValues = any, TName = any> = any;
  export const useForm: any;
  export const Controller: any;
  export const FormProvider: any;
  export const useFormContext: any;
}

declare module '@tanstack/react-router' {
  export interface ErrorComponentProps {
    error: any;
    reset: () => void;
    info?: any;
  }
  export const Link: any;
  export const Outlet: any;
  export const HeadContent: any;
  export const Scripts: any;
  export const createRootRoute: any;
  export function createRootRouteWithContext<TContext = any>(): (options?: any) => any;
  export const createFileRoute: any;
  export const createRoute: any;
  export function createRouter<TRouteTree = any, TContext = any>(options?: any): any;
  export const RouterProvider: any;
  export const useRouter: any;
  export const rootRouteId: string;
}

declare module '@tanstack/react-query' {
  export class QueryClient {
    constructor(config?: any);
    invalidateQueries(filters?: any): Promise<void>;
  }
  export const QueryClientProvider: any;
  export const useQuery: any;
  export const useMutation: any;
}

declare module '@tanstack/react-start' {
  export const createStart: any;
  export const createServerFn: any;
  export const StartClient: any;
  export const createCsrfMiddleware: any;
  export const createMiddleware: any;
}

declare module '@tanstack/react-start/*' {
  const content: any;
  export default content;
  export const createStartHandler: any;
  export const defaultStreamHandler: any;
}

interface DialogProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  children?: any;
}

declare var __dirname: string;
