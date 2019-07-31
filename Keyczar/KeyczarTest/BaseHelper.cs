using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeyczarTest
{
    public class BaseHelper
    {
        protected void Expect<TActual>(TActual actual, NUnit.Framework.Constraints.IResolveConstraint expression)
            => NUnit.StaticExpect.Expectations.Expect(actual, expression);

        protected void Expect<TActual>(TActual actual, NUnit.Framework.Constraints.IResolveConstraint expression, string message, params object[] args)
            => NUnit.StaticExpect.Expectations.Expect(actual, expression, message, args);
            
        protected void Expect<TActual>(NUnit.Framework.Constraints.ActualValueDelegate<TActual> actual, NUnit.Framework.Constraints.IResolveConstraint expression)
            => NUnit.StaticExpect.Expectations.Expect(actual, expression);
    }
}
