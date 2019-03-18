import datetime



def get_curr_date():
    curr_date = datetime.datetime.now()

    weekday = ""
    if(curr_date.date().isoweekday() == 1):
        weekday = "Mon"
    elif(curr_date.date().isoweekday() == 2):
        weekday = "Tue"
    elif (curr_date.date().isoweekday() == 2):
        weekday = "Wen"
    elif (curr_date.date().isoweekday() == 2):
        weekday = "Thu"
    elif (curr_date.date().isoweekday() == 2):
        weekday = "Fri"
    elif (curr_date.date().isoweekday() == 2):
        weekday = "Sat"
    else:
        weekday = "Sun"

    date_string = " " + weekday + ","
    date_string += " " + str(curr_date.date().day)

    month = ""
    if(curr_date.date().month == 1):
        month = "Jan"
    elif(curr_date.date().month == 2):
        month = "Feb"
    elif (curr_date.date().month == 3):
        month = "Mar"
    elif (curr_date.date().month == 4):
        month = "Apr"
    elif (curr_date.date().month == 5):
        month = "May"
    elif (curr_date.date().month == 6):
        month = "Jun"
    elif (curr_date.date().month == 7):
        month = "Jul"
    elif (curr_date.date().month == 8):
        month = "Aug"
    elif (curr_date.date().month == 9):
        month = "Sep"
    elif (curr_date.date().month == 10):
        month = "Oct"
    elif (curr_date.date().month == 11):
        month = "Nov"
    elif (curr_date.date().month == 12):
        month = "Dec"

    date_string += " " + month

    date_string += " " + str(curr_date.date().year) + ":"

    date_string += str(curr_date.hour) + ":"
    date_string += str(curr_date.minute) + ":"
    date_string += str(curr_date.second) + " "
    date_string += "GMT"
    return date_string

now_day = datetime.datetime.now()
print(datetime.datetime.now())
print(datetime.datetime.today())
print(now_day.date().strftime('%Y-%m-%d'))
print(now_day.date().weekday())
print(now_day.date().month)
print(now_day.date().day)
print(now_day.date().year)
print(now_day.date().ctime())
print(now_day.time())
print(now_day.hour)
print(now_day.minute)
print(now_day.second)

print("currdate:::: ")
print(get_curr_date())

