import * as React from "react"
import { ChevronLeft, ChevronRight } from "lucide-react"
import { DayPicker } from "react-day-picker"

import { isSameDay, isAfter, isBefore } from "date-fns"

export type CalendarProps = React.ComponentProps<typeof DayPicker>

function Calendar({
  className,
  classNames,
  showOutsideDays = true,
  ...props
}: CalendarProps) {
  const [hoveredDate, setHoveredDate] = React.useState<Date | null>(null)
  
  // Extract selection if in range mode
  const selectedRange = props.mode === "range" ? (props.selected as { from?: Date; to?: Date }) : undefined

  return (
    <DayPicker
      onDayMouseEnter={(day) => setHoveredDate(day)}
      onDayMouseLeave={() => setHoveredDate(null)}
      modifiers={{
        range_hover: (day) => {
          if (props.mode === "range" && selectedRange?.from && !selectedRange?.to && hoveredDate) {
            if (isAfter(day, selectedRange.from) && isBefore(day, hoveredDate)) return true
            if (isBefore(day, selectedRange.from) && isAfter(day, hoveredDate)) return true
          }
          return false
        },
        range_hover_end: (day) => {
          if (props.mode === "range" && selectedRange?.from && !selectedRange?.to && hoveredDate) {
            return isSameDay(day, hoveredDate)
          }
          return false
        }
      }}
      modifiersClassNames={{
        range_hover: "bg-slate-500/10 text-text rounded-none",
        range_hover_end: "bg-slate-500/20 text-text"
      }}
      showOutsideDays={showOutsideDays}
      className={`p-3 ${className}`}
      classNames={{
        months: "flex flex-col sm:flex-row space-y-4 sm:space-x-4 sm:space-y-0",
        month: "space-y-4",
        caption: "flex justify-center pt-1 relative items-center",
        caption_label: "text-sm font-medium",
        nav: "space-x-1 flex items-center",
        nav_button: "h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100 flex justify-center items-center rounded-md hover:bg-surface-hover",
        nav_button_previous: "absolute left-1",
        nav_button_next: "absolute right-1",
        table: "w-full border-collapse space-y-1",
        head_row: "flex",
        head_cell: "text-text-subtle rounded-md w-9 font-normal text-[0.8rem]",
        row: "flex w-full mt-2",
        cell: "h-9 w-9 text-center text-sm p-0 relative focus-within:relative focus-within:z-20",
        day: "h-9 w-9 p-0 font-normal hover:bg-slate-500/20 hover:text-text rounded-md flex justify-center items-center cursor-pointer transition-colors",
        day_selected: "bg-primary text-primary-content hover:bg-primary hover:text-primary-content focus:bg-primary focus:text-primary-content",
        day_today: "bg-slate-500/10 text-text font-bold",
        day_outside: "text-text-muted opacity-50",
        day_disabled: "text-text-muted opacity-50",
        day_range_middle: "aria-selected:bg-slate-500/20 aria-selected:text-text",
        day_hidden: "invisible",
        vhidden: "sr-only",
        ...classNames,
      }}
      components={{
        IconLeft: () => <ChevronLeft className="h-4 w-4" />,
        IconRight: () => <ChevronRight className="h-4 w-4" />,
      }}
      {...props}
    />
  )
}
Calendar.displayName = "Calendar"

export { Calendar }
