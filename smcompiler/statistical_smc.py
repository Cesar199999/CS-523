import time
import math

from expression import Expression, Scalar, Secret
from protocol import ProtocolSpec
from smc_party import SMCParty


class SecureStatisticsParty(SMCParty):

    # Number of terms to use in the Taylor expansion of the exponential function.
    nb_terms = 15

    def __init__(self, client_id: str, server_host: str, server_port: int, value_dict: dict[Secret, int], secrets: list[Secret], participant_ids: list, operator: str):

        self.operator = operator
        if operator == "mean":
            expr, self.normalization_factor, self.exponent = self.average_expression(
                secrets), 1 / len(secrets), 1
        elif operator == "variance":
            expr, self.normalization_factor, self.exponent = self.variance_expression(
                secrets), 1 / len(secrets) ** 2, 1
        elif operator == "geometric_mean":
            expr, self.normalization_factor, self.exponent = self.geometric_mean_expression(
                secrets), 1, 1 / len(secrets)
        elif operator == "sum_of_exponentials":
            expr, self.normalization_factor, self.exponent = self.sum_of_exponentials_expression(
                secrets), 1 / math.factorial(self.nb_terms), 1
        else:
            raise ValueError(
                f"Operator {operator} not supported. Supported operators are: mean, variance, geometric_mean, sum_of_exponentials.")

        super().__init__(client_id, server_host, server_port,
                         ProtocolSpec(participant_ids, expr), value_dict)

    def run(self) -> float:
        """
        Runs the protocol and returns the result.
        Note that the result is normalized by the normalization factor.
        Expressions must only contain integers, for this reason
        we need to normalize the expression AFTER the computation.
        """
        value = super().run()
        return self.normalization_factor * math.pow(value, self.exponent)

    def moment_of_order_expression(self, secrets: list[Secret], order: int) -> Expression:
        """
        Computes the moment of order `order` of the Secrets hold by the parties.
        """
        secret_power_order = [math.prod(
            [secret for _ in range(order-1)], start=secret) for secret in secrets]
        return sum(secret_power_order[1:], start=secret_power_order[0])

    def average_expression(self, secrets: list[Secret]) -> Expression:
        """
        Returns the expression for the average of the secrets.
        """
        return self.moment_of_order_expression(secrets, 1)

    def variance_expression(self, secrets: list[Secret]) -> Expression:
        """
        Returns the expression for the variance of the secrets.
        """

        average_expression = self.average_expression(secrets)
        moment_of_order_2_expression = self.moment_of_order_expression(
            secrets, 2)
        return moment_of_order_2_expression * Scalar(len(secrets)) - average_expression * average_expression

    def geometric_mean_expression(self, secrets: list[Secret]) -> Expression:
        """
        Returns the expression for the geometric mean of the secrets.
        """

        return math.prod(secrets[1:], start=secrets[0])

    def sum_of_exponentials_expression(self, secrets: Secret) -> Expression:
        """
        WARNING: THIS IS A COMPUTATIONALLY EXPENSIVE FUNCTION AND CAN BECOME INFEASIBLE FOR LARGE SECRET VALUES.
        Returns the sum of the exponentials of the secrets.
        """
        tmp = [self.exponential_secret_mclaurin(secret) for secret in secrets]
        return sum(tmp[1:], start=tmp[0])

    def exponential_secret_mclaurin(self, secret: Secret) -> Expression:
        """
        WARNING: EACH SECRET WILL BE EXPANDED TO O(n^2) MULTIPICATIONS.
        Returns the expression of the exponential of the secret.
        exp(secret) = 1 + secret + secret^2/2! + secret^3/3! + ... + secret^k/k!
        = 1/k! * (secret^k + k * secret^(k-1) + k * (k-1) * secret^(k-2) + ... + k! * secret^0)
        = 1/k! * (secret^k * (k!/k!) +  secret^(k-1) * (k-1)!/k! + secret^(k-2) * (k-2)!/k! + ... + k! * secret^0)
        """
        secret_powers = [self.secret_power(secret, i) * Scalar(int(math.factorial(self.nb_terms) / math.factorial(i)))
                         for i in range(self.nb_terms+1)]
        expo = sum(secret_powers[1:], start=secret_powers[0])
        return expo

    def secret_power(self, secret: Secret, n: int) -> Expression:
        """
        Returns the n-th power of the secret.
        """
        if n == 0:
            return Scalar(1)
        return math.prod([secret for _ in range(n-1)], start=secret)
