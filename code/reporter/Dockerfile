
FROM public.ecr.aws/lambda/python:3.10

COPY . ${LAMBDA_TASK_ROOT}
RUN pip install -r requirements.txt

CMD [ "lambda_function.handler" ]