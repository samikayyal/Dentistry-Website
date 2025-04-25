import enum
from dataclasses import dataclass


class QuestionType(enum.Enum):
    MULTIPLE_CHOICE = 1
    TRUE_FALSE = 2
    MULTIPLE_ANSWER = 3


# TODO: Add the ability to have multiple correct answers - Addressed
@dataclass
class Question:
    question_id: int
    question: str
    question_type: QuestionType
    correct_answers: list[int]
    options: list[str]
    topic: str


@dataclass
class __SelectedQuestions:
    __selected_questions: list[Question]
    __user_answers: dict[int, list[int]]

    def clear(self) -> None:
        self.__selected_questions.clear()
        self.__user_answers.clear()

    def update_answer(self, question_id: int, answer: list[int]) -> None:
        self.__user_answers[question_id] = answer

    def add_questions(self, questions: list[Question]) -> None:
        # Clear previous state before adding new questions
        self.clear()

        for question in questions:
            self.__selected_questions.append(question)

    def get_num_correct_answers(self) -> int:
        num_correct = 0
        for question in self.__selected_questions:
            # Check if the user actually answered this question
            user_answer = self.__user_answers.get(question.question_id)
            if user_answer is not None:  # Check if answer exists
                # Compare sets for order independence
                if set(question.correct_answers) == set(user_answer):
                    num_correct += 1
        return num_correct

    def get_total_questions(self) -> int:
        """Returns the total number of questions in the current selection."""
        return len(self.__selected_questions)

    def get_selected_questions(self) -> list[Question]:
        """Returns the list of selected questions."""
        return self.__selected_questions

    def get_user_answers(self) -> dict[int, list[int]]:
        """Returns the dictionary of user answers."""
        return self.__user_answers


selected_questions = __SelectedQuestions(
    [],
    {}
)
