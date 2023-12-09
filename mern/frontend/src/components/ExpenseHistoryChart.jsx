import React, { useMemo } from "react";
import { Chart } from "react-google-charts";
function ExpenseHistoryChart({ categories, expenses }) {
  const chartData = useMemo(() => {
    if (categories.length) {
      var result = Array(12);
      for (let i = 0; i < 12; i++) {
        const date = new Date();
        date.setMonth(i); // Adjust month number to be zero-based

        result[i] = [date.toLocaleString("default", { month: "long" })];
      }
      var categoriesList = categories.map((c) => c.name);
      categoriesList.unshift("month");
      for (let month = 1; month <= 12; month++) {
        categories.forEach((x) => {
          const expensesInThisCategory = expenses.filter(
            (y) =>
              y.category._id == x._id &&
              new Date(expenses[0].date).getMonth() + 1 == month
          );
          const totalExpenses = expensesInThisCategory.reduce(
            (acc, cur) => acc + cur.amount,
            0
          );
          result[month - 1].push(totalExpenses);
        });
      }
      result.unshift(categoriesList);
      return result;
    }
  }, [categories, expenses]);
  const data = [
    [
      "Day",
      "Guardians of the Galaxy",
      "The Avengers",
      "Transformers: Age of Extinction",
    ],
    [1, 37.8, 80.8, 41.8],
    [2, 30.9, 69.5, 32.4],
    [3, 25.4, 57, 25.7],
    [4, 11.7, 18.8, 10.5],
    [5, 11.9, 17.6, 10.4],
    [6, 8.8, 13.6, 7.7],
    [7, 7.6, 12.3, 9.6],
    [8, 12.3, 29.2, 10.6],
    [9, 16.9, 42.9, 14.8],
    [10, 12.8, 30.9, 11.6],
    [11, 5.3, 7.9, 4.7],
    [12, 6.6, 8.4, 5.2],
    [13, 4.8, 6.3, 3.6],
    [14, 4.2, 6.2, 3.4],
  ];
  const options = {
    height: 500,
    chart: {
      title: "Category Wise Expense History",
    },
  };

  return (
    <div
      style={{
        background: "#eff0f4",
        padding: "30px 0px",
      }}
    >
      <Chart
        chartType="Line"
        width="80%"
        // height="400px"
        style={{
          margin: "auto",
        }}
        data={chartData}
        options={options}
      />
    </div>
  );
}

export default ExpenseHistoryChart;
